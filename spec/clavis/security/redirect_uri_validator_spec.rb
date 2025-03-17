# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::RedirectUriValidator" do
  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "redirect URI validation" do
    it "validates URIs against a whitelist" do
      # Setup
      Clavis.configure do |config|
        config.allowed_redirect_hosts = ["example.com", "myapp.org"]
      end

      # Test valid URIs
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://example.com/callback")).to be true
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://myapp.org/auth/callback")).to be true
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://subdomain.example.com/callback")).to be true

      # Test invalid URIs
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://attacker.com/callback")).to be false
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://example.com.attacker.net/callback")).to be false
    end

    it "validates URIs with exact matching when configured" do
      # Setup
      Clavis.configure do |config|
        config.exact_redirect_uri_matching = true
        config.providers[:google] = {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "https://example.com/auth/google/callback"
        }
      end

      # Test exact URI matching
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/google/callback"
        )
      ).to be true

      # Test invalid URIs with exact matching
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/google/callback?extra=param"
        )
      ).to be false
    end

    it "validates URIs with path matching when exact matching is disabled" do
      # Setup
      Clavis.configure do |config|
        config.exact_redirect_uri_matching = false
        config.providers[:google] = {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "https://example.com/auth/google/callback"
        }
      end

      # Test path matching
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/google/callback?code=123&state=abc"
        )
      ).to be true

      # Test invalid URIs with path matching
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/different/callback"
        )
      ).to be false
    end

    it "validates localhost URIs in development" do
      # Setup
      allow(Rails).to receive(:env).and_return("development".inquiry)

      Clavis.configure do |config|
        config.allowed_redirect_hosts = ["example.com"]
        config.allow_localhost_in_development = true
      end

      # Test localhost in development
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("http://localhost:3000/callback")).to be true
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("http://127.0.0.1:3000/callback")).to be true
    end

    it "rejects localhost URIs in production" do
      # Setup
      allow(Rails).to receive(:env).and_return("production".inquiry)

      Clavis.configure do |config|
        config.allowed_redirect_hosts = ["example.com"]
        config.allow_localhost_in_development = true
      end

      # Test localhost in production
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("http://localhost:3000/callback")).to be false
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("http://127.0.0.1:3000/callback")).to be false
    end
  end

  describe "validation with exceptions" do
    it "raises an exception for invalid URIs when configured to do so" do
      # Setup
      Clavis.configure do |config|
        config.allowed_redirect_hosts = ["example.com"]
        config.raise_on_invalid_redirect = true
      end

      # Test exception for invalid URI
      expect do
        Clavis::Security::RedirectUriValidator.validate_uri!("https://attacker.com/callback")
      end.to raise_error(Clavis::InvalidRedirectUri)
    end

    it "returns false for invalid URIs when not configured to raise exceptions" do
      # Setup
      Clavis.configure do |config|
        config.allowed_redirect_hosts = ["example.com"]
        config.raise_on_invalid_redirect = false
      end

      # Test return value for invalid URI
      expect(Clavis::Security::RedirectUriValidator.validate_uri!("https://attacker.com/callback")).to be false
    end
  end
end
