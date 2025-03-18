# frozen_string_literal: true

require "spec_helper"

# Test the core authentication flow without requiring Rails
RSpec.describe "Authentication Flow", type: :model do
  before do
    # Configure Clavis for testing
    Clavis.configure do |c|
      c.providers = {
        google: {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "http://localhost:3000/auth/google/callback"
        }
      }
    end
  end

  describe "Provider configuration" do
    it "correctly identifies configured providers" do
      expect(Clavis.configuration.providers.key?(:google)).to be true
      expect(Clavis.configuration.providers.key?(:unknown)).to be false
    end

    it "can access provider configuration" do
      config = Clavis.configuration.providers[:google]
      expect(config[:client_id]).to eq("test-client-id")
      expect(config[:client_secret]).to eq("test-client-secret")
    end
  end

  describe "Provider instantiation" do
    it "instantiates a provider object" do
      provider = Clavis.provider(:google)
      expect(provider).to be_a(Clavis::Providers::Google)
    end

    it "raises an error for unsupported providers" do
      expect do
        Clavis.provider(:unsupported_provider)
      end.to raise_error(Clavis::UnsupportedProvider)
    end
  end
end
