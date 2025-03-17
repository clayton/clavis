# frozen_string_literal: true

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
      expect(provider.userinfo_endpoint).to eq("https://openidconnect.googleapis.com/v1/userinfo")
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
    it "returns a properly formatted authorization URL" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://accounts.google.com/o/oauth2/v2/auth?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgoogle%2Fcallback")
      expect(url).to include("scope=openid+email+profile")
      expect(url).to include("state=test-state")
      expect(url).to include("nonce=test-nonce")
    end

    it "uses custom scopes if provided" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce", scope: "email")

      expect(url).to include("scope=email")
      expect(url).not_to include("scope=openid+email+profile")
    end
  end
end
