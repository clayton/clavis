# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::RedirectUriValidator" do
  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "redirect URI validation" do
    it "validates URIs against a whitelist" do
      # Configure allowed hosts
      Clavis.configuration.allowed_redirect_hosts = ["example.com", "myapp.com"]

      # Valid URIs
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://example.com/callback")).to be true
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://myapp.com/auth/callback")).to be true

      # Invalid URIs
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://evil.com/callback")).to be false
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://example.com.evil.com/callback")).to be false
    end

    it "validates URIs with exact matching when configured" do
      # Configure allowed hosts and exact matching
      Clavis.configuration.allowed_redirect_hosts = ["example.com"]
      Clavis.configuration.exact_redirect_uri_matching = true

      # Configure provider redirect URI
      Clavis.configuration.providers = {
        google: {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "https://example.com/auth/google/callback"
        }
      }

      # Valid URI (exact match)
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/google/callback"
        )
      ).to be true

      # Invalid URI (different path)
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/google/callback/extra"
        )
      ).to be false

      # Invalid URI (query parameters)
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/google/callback?code=123"
        )
      ).to be false
    end

    it "validates URIs with path matching when exact matching is disabled" do
      # Configure allowed hosts and disable exact matching
      Clavis.configuration.allowed_redirect_hosts = ["example.com"]
      Clavis.configuration.exact_redirect_uri_matching = false

      # Configure provider redirect URI
      Clavis.configuration.providers = {
        google: {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "https://example.com/auth/google/callback"
        }
      }

      # Valid URI (with query parameters)
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/google/callback?code=123&state=abc"
        )
      ).to be true

      # Invalid URI (different path)
      expect(
        Clavis::Security::RedirectUriValidator.valid_provider_uri?(
          :google,
          "https://example.com/auth/different/callback"
        )
      ).to be false
    end

    it "validates localhost URIs in development" do
      # Configure allowed hosts and allow localhost in development
      Clavis.configuration.allowed_redirect_hosts = ["example.com"]
      Clavis.configuration.allow_localhost_in_development = true

      # Mock Rails.env to return development
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("development"))

      # Valid localhost URI in development
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("http://localhost:3000/callback")).to be true
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("http://127.0.0.1:3000/callback")).to be true
    end

    it "rejects localhost URIs in production" do
      # Configure allowed hosts and allow localhost in development
      Clavis.configuration.allowed_redirect_hosts = ["example.com"]
      Clavis.configuration.allow_localhost_in_development = true

      # Mock Rails.env to return production
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("production"))

      # Localhost URIs should be rejected in production
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("http://localhost:3000/callback")).to be false
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("http://127.0.0.1:3000/callback")).to be false
    end
  end

  describe "validation with exceptions" do
    it "raises an exception for invalid URIs when configured to do so" do
      # Configure allowed hosts and enable raising exceptions
      Clavis.configuration.allowed_redirect_hosts = ["example.com"]
      Clavis.configuration.raise_on_invalid_redirect = true

      # Valid URI should not raise an exception
      expect do
        Clavis::Security::RedirectUriValidator.validate_uri!("https://example.com/callback")
      end.not_to raise_error

      # Invalid URI should raise an exception
      expect do
        Clavis::Security::RedirectUriValidator.validate_uri!("https://evil.com/callback")
      end.to raise_error(Clavis::InvalidRedirectUri)
    end

    it "returns false for invalid URIs when not configured to raise exceptions" do
      # Configure allowed hosts and disable raising exceptions
      Clavis.configuration.allowed_redirect_hosts = ["example.com"]
      Clavis.configuration.raise_on_invalid_redirect = false

      # Valid URI should return true
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://example.com/callback")).to be true

      # Invalid URI should return false
      expect(Clavis::Security::RedirectUriValidator.valid_uri?("https://evil.com/callback")).to be false
    end
  end
end
