# frozen_string_literal: true

require "openssl"
require "base64"
require "json"

module Clavis
  module Security
    module TokenStorage
      class << self
        # Encrypts a token if encryption is enabled in configuration
        # @param token [String, Hash] The token to encrypt
        # @return [String, Hash] The encrypted token or the original token if encryption is disabled
        def encrypt(token)
          return token unless Clavis.configuration.encrypt_tokens
          return token if token.nil?

          key = Clavis.configuration.effective_encryption_key
          return token if key.nil?

          # Convert hash to JSON string if token is a hash
          token_str = token.is_a?(Hash) ? JSON.generate(token) : token.to_s

          cipher = OpenSSL::Cipher.new("AES-256-CBC")
          cipher.encrypt
          cipher.key = normalize_key(key)
          iv = cipher.random_iv

          encrypted = cipher.update(token_str) + cipher.final
          Base64.strict_encode64("#{Base64.strict_encode64(iv)}--#{Base64.strict_encode64(encrypted)}")
        end

        # Decrypts a token if encryption is enabled in configuration
        # @param encrypted_token [String] The encrypted token to decrypt
        # @return [String, Hash] The decrypted token or the original token if encryption is disabled
        def decrypt(encrypted_token)
          return encrypted_token unless Clavis.configuration.encrypt_tokens
          return encrypted_token if encrypted_token.nil?

          key = Clavis.configuration.effective_encryption_key
          return encrypted_token if key.nil?

          begin
            decoded = Base64.strict_decode64(encrypted_token)
            iv_b64, data_b64 = decoded.split("--", 2)

            iv = Base64.strict_decode64(iv_b64)
            data = Base64.strict_decode64(data_b64)

            decipher = OpenSSL::Cipher.new("AES-256-CBC")
            decipher.decrypt
            decipher.key = normalize_key(key)
            decipher.iv = iv

            decrypted = decipher.update(data) + decipher.final

            # Try to parse as JSON in case it's a hash
            begin
              JSON.parse(decrypted, symbolize_names: true)
            rescue JSON::ParserError
              decrypted
            end
          rescue StandardError => e
            Clavis.logger.error("Failed to decrypt token: #{e.message}")
            encrypted_token
          end
        end

        # Returns a serializer for use with ActiveRecord::Encryption
        # This allows tokens to be automatically encrypted when stored in the database
        # @return [Object] A serializer object with serialize and deserialize methods
        def active_record_serializer
          Serializer.new
        end

        private

        # Ensures the encryption key is the correct length for AES-256
        def normalize_key(key)
          if key.bytesize < 32
            # Pad the key if it's too short
            key.ljust(32, "0")
          elsif key.bytesize > 32
            # Use a digest if the key is too long
            Digest::SHA256.digest(key)
          else
            key
          end
        end
      end

      # Serializer class for ActiveRecord::Encryption
      class Serializer
        # Serialize and encrypt a token
        # @param token [String, Hash] The token to serialize
        # @return [String] The serialized and encrypted token
        def dump(token)
          TokenStorage.encrypt(token)
        end

        # Deserialize and decrypt a token
        # @param encrypted_token [String] The encrypted token to deserialize
        # @return [String, Hash] The deserialized and decrypted token
        def load(encrypted_token)
          TokenStorage.decrypt(encrypted_token)
        end

        # Alias methods for compatibility with different ActiveRecord versions
        alias serialize dump
        alias deserialize load
      end
    end
  end
end
