# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::TokenStorage" do
  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "token encryption" do
    it "encrypts tokens when encryption is enabled" do
      # Setup
      Clavis.configure do |config|
        config.encrypt_tokens = true
        config.encryption_key = "test_encryption_key_that_is_32_bytes"
      end

      # Create a mock token
      original_token = "sensitive_oauth_token_value"

      # Test encryption
      encrypted_token = Clavis::Security::TokenStorage.encrypt(original_token)

      # Assertions
      expect(encrypted_token).not_to eq(original_token)
      expect(encrypted_token).not_to include(original_token)
    end

    it "decrypts tokens correctly" do
      # Setup
      Clavis.configure do |config|
        config.encrypt_tokens = true
        config.encryption_key = "test_encryption_key_that_is_32_bytes"
      end

      # Create and encrypt a token
      original_token = "sensitive_oauth_token_value"
      encrypted_token = Clavis::Security::TokenStorage.encrypt(original_token)

      # Test decryption
      decrypted_token = Clavis::Security::TokenStorage.decrypt(encrypted_token)

      # Assertions
      expect(decrypted_token).to eq(original_token)
    end

    it "returns tokens unchanged when encryption is disabled" do
      # Setup
      Clavis.configure do |config|
        config.encrypt_tokens = false
      end

      # Create a token
      original_token = "sensitive_oauth_token_value"

      # Test with encryption disabled
      result = Clavis::Security::TokenStorage.encrypt(original_token)

      # Assertions
      expect(result).to eq(original_token)
    end
  end

  describe "Rails credentials integration" do
    before do
      # Mock Rails.application.credentials
      allow(Rails).to receive_message_chain(:application, :credentials) do
        double(
          clavis: {
            encryption_key: "credentials_encryption_key_32_bytes",
            providers: {
              google: {
                client_id: "google_client_id_from_credentials",
                client_secret: "google_client_secret_from_credentials"
              }
            }
          }
        )
      end
    end

    it "uses encryption key from Rails credentials when available" do
      # Setup
      Clavis.configure do |config|
        config.encrypt_tokens = true
        config.use_rails_credentials = true
      end

      # Create a mock token
      original_token = "sensitive_oauth_token_value"

      # Test encryption with Rails credentials
      encrypted_token = Clavis::Security::TokenStorage.encrypt(original_token)

      # Assertions
      expect(encrypted_token).not_to eq(original_token)
      expect(Clavis::Security::TokenStorage.decrypt(encrypted_token)).to eq(original_token)
    end

    it "loads provider configuration from Rails credentials when enabled" do
      # Setup
      Clavis.configure do |config|
        config.use_rails_credentials = true
      end

      # Test provider configuration from Rails credentials
      provider = Clavis.provider(:google)

      # Assertions
      expect(provider.client_id).to eq("google_client_id_from_credentials")
      expect(provider.client_secret).to eq("google_client_secret_from_credentials")
    end
  end

  describe "token serialization for ActiveRecord" do
    it "provides a serializer for ActiveRecord encrypted attributes" do
      serializer = Clavis::Security::TokenStorage.active_record_serializer

      # Test serialization
      original_token = "sensitive_oauth_token_value"
      serialized = serializer.serialize(original_token)
      deserialized = serializer.deserialize(serialized)

      # Assertions
      expect(deserialized).to eq(original_token)
    end
  end
end
