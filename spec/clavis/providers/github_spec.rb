# frozen_string_literal: true

RSpec.describe Clavis::Providers::Github do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/github/callback"
    }
  end

  let(:provider) { described_class.new(config) }

  describe "#provider_name" do
    it "returns :github" do
      expect(provider.provider_name).to eq(:github)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the GitHub authorization endpoint" do
      expect(provider.authorization_endpoint).to eq("https://github.com/login/oauth/authorize")
    end
  end

  describe "#token_endpoint" do
    it "returns the GitHub token endpoint" do
      expect(provider.token_endpoint).to eq("https://github.com/login/oauth/access_token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the GitHub userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://api.github.com/user")
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for GitHub" do
      expect(provider.default_scopes).to eq("user:email")
    end
  end

  describe "#authorize_url" do
    it "returns a properly formatted authorization URL" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://github.com/login/oauth/authorize?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgithub%2Fcallback")
      expect(url).to include("scope=user%3Aemail")
      expect(url).to include("state=test-state")
    end
  end
end
