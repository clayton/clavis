# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::HttpsEnforcer" do
  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "HTTPS enforcement" do
    it "enforces HTTPS for authorization URLs" do
      # Setup
      Clavis.configure do |config|
        config.enforce_https = true
        config.providers[:google] = {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "http://example.com/callback"
        }
      end

      provider = Clavis.provider(:google)

      # Generate an authorization URL
      auth_url = provider.authorize_url(
        state: "test_state",
        nonce: "test_nonce",
        scope: "email profile"
      )

      # Verify the URL was upgraded to HTTPS
      expect(auth_url).to start_with("https://")
      expect(auth_url).not_to start_with("http://")
    end

    it "enforces HTTPS for redirect URIs" do
      # Setup
      Clavis.configure do |config|
        config.enforce_https = true
        config.providers[:google] = {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "http://example.com/callback"
        }
      end

      provider = Clavis.provider(:google)

      # Check that the redirect URI was upgraded to HTTPS
      expect(provider.redirect_uri).to start_with("https://")
      expect(provider.redirect_uri).not_to start_with("http://")
    end

    it "allows HTTP for localhost in development" do
      # Setup
      allow(Rails).to receive(:env).and_return("development".inquiry)

      Clavis.configure do |config|
        config.enforce_https = true
        config.allow_http_localhost = true
        config.providers[:google] = {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "http://localhost:3000/callback"
        }
      end

      provider = Clavis.provider(:google)

      # Check that localhost URLs are not upgraded to HTTPS in development
      expect(provider.redirect_uri).to start_with("http://localhost")
    end

    it "enforces HTTPS for localhost in production" do
      # Setup
      allow(Rails).to receive(:env).and_return("production".inquiry)

      Clavis.configure do |config|
        config.enforce_https = true
        config.allow_http_localhost = false
        config.providers[:google] = {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "http://localhost:3000/callback"
        }
      end

      provider = Clavis.provider(:google)

      # Check that localhost URLs are upgraded to HTTPS in production
      expect(provider.redirect_uri).to start_with("https://")
    end

    it "does not enforce HTTPS when disabled" do
      # Setup
      Clavis.configure do |config|
        config.enforce_https = false
        config.providers[:google] = {
          client_id: "test_client_id",
          client_secret: "test_client_secret",
          redirect_uri: "http://example.com/callback"
        }
      end

      provider = Clavis.provider(:google)

      # Check that HTTP URLs are not upgraded when enforcement is disabled
      expect(provider.redirect_uri).to start_with("http://")
    end
  end

  describe "TLS version enforcement" do
    it "enforces minimum TLS version for HTTP client" do
      # Setup
      Clavis.configure do |config|
        config.enforce_https = true
        config.minimum_tls_version = :TLS1_2
      end

      # Get a new HTTP client with TLS enforcement
      http_client = Clavis::Security::HttpsEnforcer.create_http_client

      # Verify TLS settings
      expect(http_client.ssl.min_version).to eq(:TLS1_2)
    end
  end

  describe "certificate validation" do
    it "enables certificate validation by default" do
      # Setup
      Clavis.configure do |config|
        config.enforce_https = true
      end

      # Get a new HTTP client with certificate validation
      http_client = Clavis::Security::HttpsEnforcer.create_http_client

      # Verify certificate validation is enabled
      expect(http_client.ssl.verify).to be true
    end

    it "allows disabling certificate validation in development" do
      # Setup
      allow(Rails).to receive(:env).and_return("development".inquiry)

      Clavis.configure do |config|
        config.enforce_https = true
        config.verify_ssl = false
      end

      # Get a new HTTP client with certificate validation disabled
      http_client = Clavis::Security::HttpsEnforcer.create_http_client

      # Verify certificate validation is disabled
      expect(http_client.ssl.verify).to be false
    end

    it "enforces certificate validation in production regardless of configuration" do
      # Setup
      allow(Rails).to receive(:env).and_return("production".inquiry)

      Clavis.configure do |config|
        config.enforce_https = true
        config.verify_ssl = false # This should be ignored in production
      end

      # Get a new HTTP client in production
      http_client = Clavis::Security::HttpsEnforcer.create_http_client

      # Verify certificate validation is always enabled in production
      expect(http_client.ssl.verify).to be true
    end
  end
end
