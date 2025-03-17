# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::Providers::Google do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/google/callback"
    }
  end

  let(:provider) { described_class.new(config) }

  describe "#initialize" do
    it "sets the client_id, client_secret, and redirect_uri" do
      expect(provider.client_id).to eq("test-client-id")
      expect(provider.client_secret).to eq("test-client-secret")
      expect(provider.redirect_uri).to eq("https://example.com/auth/google/callback")
    end

    context "when configuration is missing" do
      it "raises an error when client_id is missing" do
        config.delete(:client_id)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end

      it "raises an error when client_secret is missing" do
        config.delete(:client_secret)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end

      it "raises an error when redirect_uri is missing" do
        config.delete(:redirect_uri)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end
    end
  end

  describe "#provider_name" do
    it "returns :google" do
      expect(provider.provider_name).to eq(:google)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the Google authorization endpoint" do
      expect(provider.authorization_endpoint).to eq("https://accounts.google.com/o/oauth2/v2/auth")
    end
  end

  describe "#token_endpoint" do
    it "returns the Google token endpoint" do
      expect(provider.token_endpoint).to eq("https://oauth2.googleapis.com/token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the Google userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://www.googleapis.com/oauth2/v3/userinfo")
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for Google" do
      expect(provider.default_scopes).to eq("openid email profile")
    end
  end

  describe "#openid_provider?" do
    it "returns true" do
      expect(provider.openid_provider?).to be true
    end
  end

  describe "#authorize_url" do
    it "includes the required parameters" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://accounts.google.com/o/oauth2/v2/auth")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgoogle%2Fcallback")
      expect(url).to include("scope=openid+email+profile")
      expect(url).to include("state=test-state")
      expect(url).to include("nonce=test-nonce")
    end

    it "includes access_type=offline and prompt=consent for refresh token support" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to include("access_type=offline")
      expect(url).to include("prompt=consent")
    end

    it "allows custom scopes" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce", scope: "openid email")

      expect(url).to include("scope=openid+email")
    end
  end

  describe "#token_exchange" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response_body) do
      {
        access_token: "test-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "test-refresh-token",
        id_token: "test-id-token"
      }.to_json
    end
    let(:response) { instance_double(Faraday::Response, status: 200, body: response_body) }

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
        refresh_token: "test-refresh-token",
        id_token: "test-id-token"
      )
    end
  end
end
