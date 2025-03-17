# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::Providers::Apple do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/apple/callback",
      private_key: "test-private-key",
      team_id: "test-team-id",
      key_id: "test-key-id"
    }
  end

  let(:provider) { described_class.new(config) }

  before do
    # Mock the OpenSSL and JWT methods
    allow(OpenSSL::PKey::EC).to receive(:new).and_return(double("private_key"))
    allow(JWT).to receive(:encode).and_return("test-jwt-token")
  end

  describe "#provider_name" do
    it "returns :apple" do
      expect(provider.provider_name).to eq(:apple)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the Apple authorization endpoint" do
      expect(provider.authorization_endpoint).to eq("https://appleid.apple.com/auth/authorize")
    end
  end

  describe "#token_endpoint" do
    it "returns the Apple token endpoint" do
      expect(provider.token_endpoint).to eq("https://appleid.apple.com/auth/token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns nil as Apple doesn't have a userinfo endpoint" do
      expect(provider.userinfo_endpoint).to be_nil
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for Apple" do
      expect(provider.default_scopes).to eq("name email")
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

      expect(url).to start_with("https://appleid.apple.com/auth/authorize?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fapple%2Fcallback")
      expect(url).to include("scope=name+email")
      expect(url).to include("state=test-state")
    end
  end

  describe "#refresh_token" do
    it "raises an UnsupportedOperation error" do
      expect do
        provider.refresh_token("some_refresh_token")
      end.to raise_error(Clavis::UnsupportedOperation, "Unsupported operation: Apple does not support refresh tokens")
    end
  end

  describe "#get_user_info" do
    it "raises an UnsupportedOperation error" do
      expect do
        provider.get_user_info("some_access_token")
      end.to raise_error(Clavis::UnsupportedOperation, "Unsupported operation: Apple does not have a userinfo endpoint")
    end
  end
end
