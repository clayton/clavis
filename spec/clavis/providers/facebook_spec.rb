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
      expect(provider.authorization_endpoint).to eq("https://www.facebook.com/v18.0/dialog/oauth")
    end
  end

  describe "#token_endpoint" do
    it "returns the Facebook token endpoint" do
      expect(provider.token_endpoint).to eq("https://graph.facebook.com/v18.0/oauth/access_token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the Facebook userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://graph.facebook.com/v18.0/me")
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

      expect(url).to start_with("https://www.facebook.com/v18.0/dialog/oauth?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Ffacebook%2Fcallback")
      expect(url).to include("scope=email+public_profile")
      expect(url).to include("state=test-state")
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
    end

    it "sends a token exchange request to get a long-lived token" do
      expected_params = {
        grant_type: "fb_exchange_token",
        client_id: "test-client-id",
        client_secret: "test-client-secret",
        fb_exchange_token: access_token
      }

      provider.refresh_token(access_token)

      expect(http_client).to have_received(:get).with(
        "https://graph.facebook.com/v18.0/oauth/access_token?#{provider.send(:to_query, expected_params)}"
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
end
