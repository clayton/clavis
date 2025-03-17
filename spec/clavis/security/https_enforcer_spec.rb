# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::HttpsEnforcer" do
  let(:http_url) { "http://example.com/callback" }
  let(:https_url) { "https://example.com/callback" }
  let(:localhost_url) { "http://localhost:3000/callback" }

  let(:provider_config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: http_url,
      authorization_endpoint: "https://example.com/auth",
      token_endpoint: "https://example.com/token",
      userinfo_endpoint: "https://example.com/userinfo"
    }
  end

  let(:provider) { Clavis::Providers::Generic.new(provider_config) }

  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "HTTPS enforcement" do
    it "enforces HTTPS for authorization URLs" do
      # Enable HTTPS enforcement
      Clavis.configuration.enforce_https = true

      # Test that HTTP URLs are converted to HTTPS
      url = Clavis::Security::HttpsEnforcer.enforce_https(http_url)
      expect(url).to start_with("https://")

      # Test that HTTPS URLs are left unchanged
      url = Clavis::Security::HttpsEnforcer.enforce_https(https_url)
      expect(url).to eq(https_url)
    end

    it "enforces HTTPS for redirect URIs" do
      # Enable HTTPS enforcement
      Clavis.configuration.enforce_https = true

      # Mock the redirect_uri method to use HttpsEnforcer
      allow(provider).to receive(:redirect_uri) do
        Clavis::Security::HttpsEnforcer.enforce_https(http_url)
      end

      # Test that the redirect URI is converted to HTTPS
      expect(provider.redirect_uri).to start_with("https://")
    end

    it "allows HTTP for localhost in development" do
      # Enable HTTPS enforcement but allow localhost
      Clavis.configuration.enforce_https = true
      Clavis.configuration.allow_http_localhost = true

      # Mock Rails.env to return development
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("development"))

      # Test that localhost URLs are left as HTTP in development
      url = Clavis::Security::HttpsEnforcer.enforce_https(localhost_url)
      expect(url).to start_with("http://")
    end

    it "enforces HTTPS for localhost in production" do
      # Enable HTTPS enforcement and allow localhost
      Clavis.configuration.enforce_https = true
      Clavis.configuration.allow_http_localhost = true

      # Mock Rails.env to return production
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("production"))

      # Mock the redirect_uri method to use HttpsEnforcer with localhost URL
      allow(provider).to receive(:redirect_uri) do
        Clavis::Security::HttpsEnforcer.enforce_https(localhost_url)
      end

      # Test that localhost URLs are converted to HTTPS in production
      expect(provider.redirect_uri).to start_with("https://")
    end

    it "does not enforce HTTPS when disabled" do
      # Disable HTTPS enforcement
      Clavis.configuration.enforce_https = false

      # Test that HTTP URLs are left unchanged
      url = Clavis::Security::HttpsEnforcer.enforce_https(http_url)
      expect(url).to start_with("http://")
    end
  end

  describe "TLS version enforcement" do
    it "enforces minimum TLS version for HTTP client" do
      # Set minimum TLS version
      Clavis.configuration.minimum_tls_version = :TLS1_2

      # Create HTTP client
      client = Clavis::Security::HttpsEnforcer.create_http_client

      # Test that the client has the correct SSL version
      expect(client.ssl.min_version).to eq(:TLS1_2)
    end
  end

  describe "certificate validation" do
    it "enables certificate validation by default" do
      # Create HTTP client with default settings
      client = Clavis::Security::HttpsEnforcer.create_http_client

      # Test that certificate validation is enabled
      expect(client.ssl.verify).to be true
    end

    it "allows disabling certificate validation in development" do
      # Disable certificate validation
      Clavis.configuration.verify_ssl = false

      # Mock Rails.env to return development
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("development"))

      # Create HTTP client
      client = Clavis::Security::HttpsEnforcer.create_http_client

      # Test that certificate validation is disabled
      expect(client.ssl.verify).to be false
    end

    it "enforces certificate validation in production regardless of configuration" do
      # Disable certificate validation
      Clavis.configuration.verify_ssl = false

      # Mock Rails.env to return production
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("production"))

      # Create HTTP client
      client = Clavis::Security::HttpsEnforcer.create_http_client

      # Test that certificate validation is still enabled in production
      expect(client.ssl.verify).to be true
    end
  end
end
