# frozen_string_literal: true

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
end
