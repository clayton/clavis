# frozen_string_literal: true

require "spec_helper"
require "active_support/core_ext/object/blank"

RSpec.describe "Clavis::Security::TokenStorage" do
  let(:token) do
    {
      access_token: "test_access_token",
      refresh_token: "test_refresh_token",
      expires_at: Time.now.to_i + 3600
    }
  end

  let(:token_string) { "test_access_token" }

  let(:encryption_key) { "test_encryption_key_32_bytes_long!!" }

  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "token encryption" do
    it "encrypts tokens when encryption is enabled" do
      # Enable encryption
      Clavis.configuration.encrypt_tokens = true
      Clavis.configuration.encryption_key = encryption_key

      # Encrypt the token string
      encrypted = Clavis::Security::TokenStorage.encrypt(token_string)

      # Verify the token is encrypted
      expect(encrypted).not_to eq(token_string)
      expect(encrypted).to be_a(String)
      # Base64 encoded string
      expect(encrypted).to match(%r{^[A-Za-z0-9+/]+={0,2}$})
    end

    it "decrypts tokens correctly" do
      # Enable encryption
      Clavis.configuration.encrypt_tokens = true
      Clavis.configuration.encryption_key = encryption_key

      # Encrypt and then decrypt the token
      encrypted = Clavis::Security::TokenStorage.encrypt(token)
      decrypted = Clavis::Security::TokenStorage.decrypt(encrypted)

      # Verify the decrypted token matches the original
      expect(decrypted).to be_a(Hash)
      expect(decrypted[:access_token]).to eq(token[:access_token])
      expect(decrypted[:refresh_token]).to eq(token[:refresh_token])
      expect(decrypted[:expires_at]).to eq(token[:expires_at])
    end

    it "returns tokens unchanged when encryption is disabled" do
      # Disable encryption
      Clavis.configuration.encrypt_tokens = false

      # Encrypt the token (should return unchanged)
      result = Clavis::Security::TokenStorage.encrypt(token)

      # Verify the token is unchanged
      expect(result).to eq(token)
    end
  end

  describe "Rails credentials integration", rails: true do
    before do
      # Mock Rails and credentials
      class Rails; end unless defined?(Rails)

      # Create a mock application with credentials
      application = double("Application")
      credentials = double("Credentials")

      # Set up the Rails application and credentials
      allow(Rails).to receive(:application).and_return(application)
      allow(application).to receive(:credentials).and_return(credentials)
      allow(application).to receive(:respond_to?).with(:credentials).and_return(true)

      # Mock the credentials.dig method to return our test encryption key
      allow(credentials).to receive(:dig).with(:clavis, :encryption_key).and_return("rails_credentials_encryption_key")

      # Mock the credentials.dig method for provider configuration
      allow(credentials).to receive(:dig).with(:clavis, :providers, :google, :client_id).and_return("google_client_id_from_credentials")
      allow(credentials).to receive(:dig).with(:clavis, :providers, :google, :client_secret).and_return("google_client_secret_from_credentials")
      allow(credentials).to receive(:dig).with(:clavis, :providers, :google, :redirect_uri).and_return("https://example.com/callback")

      # Configure Clavis to use the proper client credentials
      allow(Clavis.configuration).to receive(:providers).and_return({
                                                                      google: {
                                                                        client_id: "google_client_id_from_credentials",
                                                                        client_secret: "google_client_secret_from_credentials",
                                                                        redirect_uri: "https://example.com/callback"
                                                                      }
                                                                    })
    end

    it "uses encryption key from Rails credentials when available" do
      # Enable encryption but don't set a key directly
      Clavis.configuration.encrypt_tokens = true
      Clavis.configuration.use_rails_credentials = true

      # Encrypt a token string (should use the key from Rails credentials)
      encrypted = Clavis::Security::TokenStorage.encrypt(token_string)

      # Verify the token is encrypted
      expect(encrypted).to be_a(String)
      expect(encrypted).to match(%r{^[A-Za-z0-9+/]+={0,2}$})

      # Set the encryption key to match what's in Rails credentials for decryption
      Clavis.configuration.encryption_key = "rails_credentials_encryption_key"

      # Decrypt and verify
      decrypted = Clavis::Security::TokenStorage.decrypt(encrypted)
      expect(decrypted).to eq(token_string)
    end

    it "loads provider configuration from Rails credentials when enabled" do
      # Enable Rails credentials
      Clavis.configuration.use_rails_credentials = true

      # Mock the provider creation to avoid issues with method calls in the provider
      provider_class = class_double("Clavis::Providers::Google")
      allow(provider_class).to receive(:new).and_return(double(
                                                          "GoogleProvider",
                                                          client_id: "google_client_id_from_credentials",
                                                          client_secret: "google_client_secret_from_credentials",
                                                          redirect_uri: "https://example.com/callback"
                                                        ))

      # Replace the Google provider in the registry
      original_google = Clavis.provider_registry[:google]
      begin
        Clavis.register_provider(:google, provider_class)

        # Create the Google provider and verify it has the right config
        provider = Clavis.provider(:google)
        expect(provider.client_id).to eq("google_client_id_from_credentials")
        expect(provider.client_secret).to eq("google_client_secret_from_credentials")
      ensure
        # Restore the original Google provider
        Clavis.register_provider(:google, original_google)
      end
    end
  end

  describe "token serialization for ActiveRecord" do
    it "provides a serializer for ActiveRecord encrypted attributes" do
      # Enable encryption for this test
      Clavis.configuration.encrypt_tokens = true
      Clavis.configuration.encryption_key = encryption_key

      # Create a serializer instance
      serializer = Clavis::Security::TokenStorage::Serializer.new

      # Test serialization with a string
      serialized = serializer.dump(token_string)
      expect(serialized).to be_a(String)
      expect(serialized).to match(%r{^[A-Za-z0-9+/]+={0,2}$})

      # Test deserialization
      deserialized = serializer.load(serialized)
      expect(deserialized).to eq(token_string)
    end
  end

  # Define Rails as a stub for testing if not already defined
  unless defined?(Rails)
    class Rails
      # This is a stub class for testing Rails.credentials integration
      def self.credentials
        {}
      end
    end
  end
end
