# frozen_string_literal: true

RSpec.describe Clavis::Providers::Microsoft do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/microsoft/callback",
      tenant: "test-tenant"
    }
  end

  let(:provider) { described_class.new(config) }

  describe "#provider_name" do
    it "returns :microsoft" do
      expect(provider.provider_name).to eq(:microsoft)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the Microsoft authorization endpoint with the tenant" do
      expect(provider.authorization_endpoint).to eq("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize")
    end
  end

  describe "#token_endpoint" do
    it "returns the Microsoft token endpoint with the tenant" do
      expect(provider.token_endpoint).to eq("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the Microsoft userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://graph.microsoft.com/v1.0/me")
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for Microsoft" do
      expect(provider.default_scopes).to eq("openid email profile User.Read")
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

      expect(url).to start_with("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fmicrosoft%2Fcallback")
      expect(url).to include("scope=openid+email+profile+User.Read")
      expect(url).to include("state=test-state")
      expect(url).to include("nonce=test-nonce")
    end
  end

  context "when tenant is not provided" do
    let(:config) do
      {
        client_id: "test-client-id",
        client_secret: "test-client-secret",
        redirect_uri: "https://example.com/auth/microsoft/callback"
      }
    end

    it "uses 'common' as the default tenant" do
      expect(provider.authorization_endpoint).to eq("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
      expect(provider.token_endpoint).to eq("https://login.microsoftonline.com/common/oauth2/v2.0/token")
    end
  end
end
