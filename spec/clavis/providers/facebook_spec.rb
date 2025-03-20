# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::Providers::Facebook do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/facebook/callback"
    }
  end

  let(:provider) { described_class.new(config) }

  describe "#provider_name" do
    it "returns :facebook" do
      expect(provider.provider_name).to eq(:facebook)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the Facebook authorization endpoint" do
      expect(provider.authorization_endpoint).to eq("https://www.facebook.com/v19.0/dialog/oauth")
    end
  end

  describe "#token_endpoint" do
    it "returns the Facebook token endpoint" do
      expect(provider.token_endpoint).to eq("https://graph.facebook.com/v19.0/oauth/access_token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the Facebook userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://graph.facebook.com/v19.0/me")
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for Facebook" do
      expect(provider.default_scopes).to eq("email public_profile")
    end
  end

  describe "#authorize_url" do
    it "returns a properly formatted authorization URL" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://www.facebook.com/v19.0/dialog/oauth?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Ffacebook%2Fcallback")
      expect(url).to include("scope=email+public_profile")
      expect(url).to include("state=test-state")
    end

    context "with display and auth_type options" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/facebook/callback",
          display: "popup",
          auth_type: "rerequest"
        }
      end

      it "includes the display parameter" do
        url = provider.authorize_url(state: "test-state", nonce: "test-nonce")
        expect(url).to include("display=popup")
      end

      it "includes the auth_type parameter" do
        url = provider.authorize_url(state: "test-state", nonce: "test-nonce")
        expect(url).to include("auth_type=rerequest")
      end
    end
  end

  describe "#refresh_token" do
    let(:access_token) { "test_access_token" }
    let(:response_body) do
      {
        access_token: "new_long_lived_access_token",
        token_type: "Bearer",
        expires_in: 5_184_000 # 60 days
      }.to_json
    end

    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response) { instance_double(Faraday::Response, status: 200, body: response_body) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(response)
      allow(Clavis::Logging).to receive(:log_token_refresh)
      # Allow generate_appsecret_proof method
      allow(provider).to receive(:generate_appsecret_proof).with(access_token).and_return("appsecret_proof_value")
    end

    it "sends a token exchange request to get a long-lived token" do
      expected_params = {
        grant_type: "fb_exchange_token",
        client_id: "test-client-id",
        client_secret: "test-client-secret",
        fb_exchange_token: access_token,
        appsecret_proof: "appsecret_proof_value"
      }

      provider.refresh_token(access_token)

      expect(http_client).to have_received(:get).with(
        "https://graph.facebook.com/v19.0/oauth/access_token?#{provider.send(:to_query, expected_params)}"
      )
    end

    it "returns the parsed token response" do
      result = provider.refresh_token(access_token)

      expect(result).to include(
        access_token: "new_long_lived_access_token",
        token_type: "Bearer",
        expires_in: 5_184_000
      )
    end

    it "logs a successful token refresh" do
      provider.refresh_token(access_token)

      expect(Clavis::Logging).to have_received(:log_token_refresh).with(
        :facebook,
        true
      )
    end

    context "when the token exchange fails" do
      let(:response) do
        instance_double(Faraday::Response, status: 400,
                                           body: { error: { message: "Invalid OAuth access token." } }.to_json)
      end

      before do
        allow(provider).to receive(:handle_token_error_response).and_raise(Clavis::InvalidAccessToken)
      end

      it "logs a failed token refresh" do
        expect { provider.refresh_token(access_token) }.to raise_error(Clavis::InvalidAccessToken)

        expect(Clavis::Logging).to have_received(:log_token_refresh).with(
          :facebook,
          false
        )
      end

      it "handles the error response" do
        expect { provider.refresh_token(access_token) }.to raise_error(Clavis::InvalidAccessToken)

        expect(provider).to have_received(:handle_token_error_response).with(response)
      end
    end
  end

  describe "#get_user_info" do
    let(:access_token) { "test_access_token" }
    let(:response_body) do
      {
        id: "12345",
        name: "John Doe",
        email: "john@example.com",
        first_name: "John",
        last_name: "Doe",
        picture: {
          data: {
            url: "https://graph.facebook.com/12345/picture"
          }
        },
        verified: true,
        link: "https://facebook.com/john.doe",
        location: {
          name: "San Francisco, CA"
        },
        gender: "male",
        birthday: "01/01/1990",
        age_range: {
          min: 21
        }
      }.to_json
    end

    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response) { instance_double(Faraday::Response, status: 200, body: response_body) }
    let(:faraday_request) { double("FaradayRequest") }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_yield(faraday_request).and_return(response)
      allow(faraday_request).to receive(:params).and_return({})
      allow(Clavis::Logging).to receive(:log_userinfo_request)
      allow(provider).to receive(:generate_appsecret_proof).with(access_token).and_return("appsecret_proof_value")
    end

    it "sends a user info request with the access token and fields" do
      provider.get_user_info(access_token)

      expect(http_client).to have_received(:get).with(
        "https://graph.facebook.com/v19.0/me"
      )

      expect(faraday_request).to have_received(:params).at_least(:once)
    end

    it "returns processed user info" do
      result = provider.get_user_info(access_token)

      expect(result).to include(
        id: "12345",
        name: "John Doe",
        email: "john@example.com",
        given_name: "John",
        family_name: "Doe",
        picture: "https://graph.facebook.com/12345/picture",
        verified: true,
        link: "https://facebook.com/john.doe",
        location: "San Francisco, CA",
        gender: "male",
        birthday: "01/01/1990",
        age_range: {
          min: 21
        }
      )
    end

    it "logs a successful user info request" do
      provider.get_user_info(access_token)

      expect(Clavis::Logging).to have_received(:log_userinfo_request).with(
        :facebook,
        true
      )
    end

    context "when the picture is a string" do
      let(:response_body) do
        {
          id: "12345",
          name: "John Doe",
          email: "john@example.com",
          picture: "https://direct-picture-url.jpg"
        }.to_json
      end

      it "correctly extracts the picture URL" do
        result = provider.get_user_info(access_token)
        expect(result[:picture]).to eq("https://direct-picture-url.jpg")
      end
    end

    context "when the user info request fails" do
      let(:response) do
        instance_double(Faraday::Response, status: 400,
                                           body: { error: { message: "Invalid OAuth access token." } }.to_json)
      end

      before do
        allow(provider).to receive(:handle_userinfo_error_response).and_raise(Clavis::InvalidAccessToken)
      end

      it "logs a failed user info request" do
        expect { provider.get_user_info(access_token) }.to raise_error(Clavis::InvalidAccessToken)

        expect(Clavis::Logging).to have_received(:log_userinfo_request).with(
          :facebook,
          false
        )
      end

      it "handles the error response" do
        expect { provider.get_user_info(access_token) }.to raise_error(Clavis::InvalidAccessToken)

        expect(provider).to have_received(:handle_userinfo_error_response).with(response)
      end
    end
  end

  describe "#exchange_for_long_lived_token" do
    let(:access_token) { "short_lived_access_token" }
    let(:response_body) do
      {
        access_token: "long_lived_access_token",
        token_type: "Bearer",
        expires_in: 5_184_000 # 60 days
      }.to_json
    end

    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response) { instance_double(Faraday::Response, status: 200, body: response_body) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(response)
      allow(Clavis::Logging).to receive(:log_custom)
    end

    it "exchanges a short-lived token for a long-lived token" do
      expected_params = {
        grant_type: "fb_exchange_token",
        client_id: "test-client-id",
        client_secret: "test-client-secret",
        fb_exchange_token: access_token
      }

      provider.exchange_for_long_lived_token(access_token)

      expect(http_client).to have_received(:get).with(
        "https://graph.facebook.com/v19.0/oauth/access_token?#{provider.send(:to_query, expected_params)}"
      )
    end

    it "returns the long-lived token response" do
      result = provider.exchange_for_long_lived_token(access_token)

      expect(result).to include(
        access_token: "long_lived_access_token",
        token_type: "Bearer",
        expires_in: 5_184_000
      )
    end

    it "logs a successful token exchange" do
      provider.exchange_for_long_lived_token(access_token)

      expect(Clavis::Logging).to have_received(:log_custom).with(
        "facebook_long_lived_token_exchange",
        true
      )
    end

    context "when the token exchange fails" do
      let(:response) do
        instance_double(Faraday::Response, status: 400,
                                           body: { error: { message: "Invalid OAuth access token." } }.to_json)
      end

      before do
        allow(provider).to receive(:handle_token_error_response).and_raise(Clavis::InvalidAccessToken)
      end

      it "logs a failed token exchange" do
        expect { provider.exchange_for_long_lived_token(access_token) }.to raise_error(Clavis::InvalidAccessToken)

        expect(Clavis::Logging).to have_received(:log_custom).with(
          "facebook_long_lived_token_exchange",
          false
        )
      end

      it "handles the error response" do
        expect { provider.exchange_for_long_lived_token(access_token) }.to raise_error(Clavis::InvalidAccessToken)

        expect(provider).to have_received(:handle_token_error_response).with(response)
      end
    end
  end

  describe "#generate_appsecret_proof" do
    it "generates a valid HMAC-SHA256 signature" do
      access_token = "test_access_token"
      expected_proof = OpenSSL::HMAC.hexdigest(
        OpenSSL::Digest.new("sha256"),
        "test-client-secret",
        access_token
      )

      actual_proof = provider.send(:generate_appsecret_proof, access_token)

      expect(actual_proof).to eq(expected_proof)
    end

    it "returns nil when client_secret is nil" do
      allow(provider).to receive(:client_secret).and_return(nil)

      actual_proof = provider.send(:generate_appsecret_proof, "test_access_token")

      expect(actual_proof).to be_nil
    end

    it "returns nil when access_token is nil" do
      actual_proof = provider.send(:generate_appsecret_proof, nil)

      expect(actual_proof).to be_nil
    end
  end

  describe "#image_url" do
    it "builds a URL for the user's profile picture" do
      uid = "12345"
      url = provider.send(:image_url, uid)

      expect(url).to eq("https://graph.facebook.com/v19.0/12345/picture")
    end

    context "with image size as a string" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/facebook/callback",
          image_size: "large"
        }
      end

      it "adds the size as a type parameter" do
        uid = "12345"
        url = provider.send(:image_url, uid)

        expect(url).to eq("https://graph.facebook.com/v19.0/12345/picture?type=large")
      end
    end

    context "with image size as a hash" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/facebook/callback",
          image_size: { width: 200, height: 200 }
        }
      end

      it "adds the dimensions as query parameters" do
        uid = "12345"
        url = provider.send(:image_url, uid)

        expect(url).to eq("https://graph.facebook.com/v19.0/12345/picture?width=200&height=200")
      end
    end

    context "with secure_image_url set to false" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/facebook/callback",
          secure_image_url: false
        }
      end

      it "uses HTTP instead of HTTPS" do
        uid = "12345"
        url = provider.send(:image_url, uid)

        expect(url).to start_with("http://")
      end
    end

    it "returns nil if uid is nil" do
      url = provider.send(:image_url, nil)

      expect(url).to be_nil
    end
  end
end
