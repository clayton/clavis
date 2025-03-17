# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::Providers::Generic do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/custom/callback",
      authorization_endpoint: "https://custom-provider.com/oauth/authorize",
      token_endpoint: "https://custom-provider.com/oauth/token",
      userinfo_endpoint: "https://custom-provider.com/oauth/userinfo",
      scopes: "profile email",
      openid_provider: false
    }
  end

  let(:provider) { described_class.new(config) }

  describe "#initialize" do
    it "sets the endpoints from the configuration" do
      expect(provider.authorization_endpoint).to eq("https://custom-provider.com/oauth/authorize")
      expect(provider.token_endpoint).to eq("https://custom-provider.com/oauth/token")
      expect(provider.userinfo_endpoint).to eq("https://custom-provider.com/oauth/userinfo")
      expect(provider.default_scopes).to eq("profile email")
      expect(provider.openid_provider?).to be false
    end

    context "when configuration is missing" do
      it "raises an error when authorization_endpoint is missing" do
        config.delete(:authorization_endpoint)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end

      it "raises an error when token_endpoint is missing" do
        config.delete(:token_endpoint)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end

      it "raises an error when userinfo_endpoint is missing" do
        config.delete(:userinfo_endpoint)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end
    end
  end

  describe "#provider_name" do
    it "returns :generic" do
      expect(provider.provider_name).to eq(:generic)
    end
  end

  describe "#authorize_url" do
    it "includes the required parameters" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://custom-provider.com/oauth/authorize")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fcustom%2Fcallback")
      expect(url).to include("state=test-state")
      expect(url).to include("scope=profile+email")
    end

    it "does not include nonce for non-OpenID providers" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")
      expect(url).not_to include("nonce=test-nonce")
    end

    context "with OpenID provider" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/custom/callback",
          authorization_endpoint: "https://custom-provider.com/oauth/authorize",
          token_endpoint: "https://custom-provider.com/oauth/token",
          userinfo_endpoint: "https://custom-provider.com/oauth/userinfo",
          scopes: "openid profile email",
          openid_provider: true
        }
      end

      it "includes nonce for OpenID providers" do
        url = provider.authorize_url(state: "test-state", nonce: "test-nonce")
        expect(url).to include("nonce=test-nonce")
      end
    end
  end

  describe "#token_exchange" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response) do
      instance_double(
        Faraday::Response,
        status: 200,
        body: {
          access_token: "test-access-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "test-refresh-token"
        }.to_json
      )
    end

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:post).and_return(response)
      allow(Clavis::Logging).to receive(:log_token_exchange)
    end

    it "exchanges the code for tokens" do
      result = provider.token_exchange(code: "test-code")

      expect(result).to include(
        access_token: "test-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "test-refresh-token"
      )
    end
  end

  describe "#get_user_info" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response) do
      instance_double(
        Faraday::Response,
        status: 200,
        body: {
          id: "user123",
          name: "Test User",
          email: "test@example.com"
        }.to_json
      )
    end

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(response)
    end

    it "fetches user info from the userinfo endpoint" do
      result = provider.get_user_info("test-access-token")

      expect(result).to include(
        id: "user123",
        name: "Test User",
        email: "test@example.com"
      )
    end
  end
end
