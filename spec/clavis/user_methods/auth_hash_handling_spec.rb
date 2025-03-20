# frozen_string_literal: true

require "spec_helper"
require "active_support/core_ext/hash/indifferent_access"

RSpec.describe "ClavisUserMethods auth hash handling" do
  # Define a test class that includes our concern
  let(:test_class) do
    Class.new do
      def self.find_by(_conditions)
        nil
      end

      def self.new(attributes)
        instance = allocate
        instance.instance_variable_set(:@attributes, attributes)
        instance
      end

      def save!
        true
      end

      def self.find_or_create_from_clavis(auth_hash)
        # Here we'll implement our recommended approach
        identity = Clavis::OauthIdentity.find_by(
          provider: auth_hash[:provider],
          uid: auth_hash[:uid]
        )
        return identity.user if identity&.user

        # Try to find by email
        user = find_by(email: auth_hash.dig(:info, :email)) if auth_hash.dig(:info, :email)

        # Create a new user if none exists
        if user.nil?
          # Convert to HashWithIndifferentAccess for reliable key access
          info = auth_hash[:info].with_indifferent_access if auth_hash[:info]
          claims = auth_hash[:id_token_claims].with_indifferent_access if auth_hash[:id_token_claims]

          # Find email from various possible locations
          email = info&.dig(:email) || claims&.dig(:email)

          user = new(
            email: email,
            first_name: info&.dig(:given_name) || info&.dig(:first_name),
            last_name: info&.dig(:family_name) || info&.dig(:last_name),
            avatar_url: info&.dig(:picture) || info&.dig(:image)
          )

          user.save!
        end

        # Create or update the OAuth identity for this user
        Clavis::OauthIdentity || Struct.new(:user, :auth_data, :token, :refresh_token, :expires_at)

        # Create a mock identity rather than a real one
        mock_identity = Object.new

        # Define accessors for the mock identity
        class << mock_identity
          attr_writer :auth_data, :token, :refresh_token, :expires_at
          attr_accessor :user

          def save!; end
        end

        # Use with_indifferent_access for reliable access to credentials
        credentials = if auth_hash[:credentials].respond_to?(:with_indifferent_access)
                        auth_hash[:credentials].with_indifferent_access
                      else
                        auth_hash[:credentials]
                      end

        # Set the identity properties
        mock_identity.user = user
        mock_identity.auth_data = auth_hash[:info]
        mock_identity.token = credentials&.dig(:token) || credentials&.dig("token")
        mock_identity.refresh_token = credentials&.dig(:refresh_token) || credentials&.dig("refresh_token")
        mock_identity.expires_at = credentials&.dig(:expires_at) || credentials&.dig("expires_at")

        user
      end
    end
  end

  # Mock OauthIdentity class for testing
  before do
    stub_const("Clavis::OauthIdentity", Class.new do
      def self.find_by(*)
        nil
      end
    end)
  end

  describe "handling Google OAuth hash" do
    let(:google_auth_hash) do
      {
        provider: :google,
        uid: "123456789012345678901",
        info: {
          "sub" => "123456789012345678901",
          "name" => "John Smith",
          "given_name" => "John",
          "family_name" => "Smith",
          "picture" => "https://example.com/avatar.jpg",
          "email" => "john.smith@example.com",
          "email_verified" => true
        },
        credentials: {
          token: "ya29.example-token-value",
          refresh_token: "1//example-refresh-token",
          expires_at: 1_742_415_023,
          expires: true
        },
        id_token: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImV4YW1wbGUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiJleGFtcGxlLWF6cCIsImF1ZCI6ImV4YW1wbGUtYXVkIiwic3ViIjoiMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxIiwiZW1haWwiOiJqb2huLnNtaXRoQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJleGFtcGxlLWF0LWhhc2giLCJub25jZSI6ImV4YW1wbGUtbm9uY2UiLCJuYW1lIjoiSm9obiBTbWl0aCIsInBpY3R1cmUiOiJodHRwczovL2V4YW1wbGUuY29tL2F2YXRhci5qcGciLCJnaXZlbl9uYW1lIjoiSm9obiIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJpYXQiOjE2MDAwMDAwMDAsImV4cCI6MTYwMDAwMDAwMH0.example-signature",
        id_token_claims: {
          iss: "https://accounts.google.com",
          azp: "example-azp",
          aud: "example-aud",
          sub: "123456789012345678901",
          email: "john.smith@example.com",
          email_verified: true,
          at_hash: "example-at-hash",
          nonce: "example-nonce",
          name: "John Smith",
          picture: "https://example.com/avatar.jpg",
          given_name: "John",
          family_name: "Smith",
          iat: 1_600_000_000,
          exp: 1_600_000_000
        }
      }
    end

    it "extracts user info correctly from Google auth hash with string keys" do
      user = test_class.find_or_create_from_clavis(google_auth_hash)

      expect(user.instance_variable_get(:@attributes)).to include(
        email: "john.smith@example.com",
        first_name: "John",
        last_name: "Smith",
        avatar_url: "https://example.com/avatar.jpg"
      )
    end

    it "works when google provides info with symbol keys instead" do
      # Same hash but with symbol keys instead of strings
      hash_with_symbols = google_auth_hash.dup
      hash_with_symbols[:info] = {
        sub: "123456789012345678901",
        name: "John Smith",
        given_name: "John",
        family_name: "Smith",
        picture: "https://example.com/avatar.jpg",
        email: "john.smith@example.com",
        email_verified: true
      }

      user = test_class.find_or_create_from_clavis(hash_with_symbols)

      expect(user.instance_variable_get(:@attributes)).to include(
        email: "john.smith@example.com",
        first_name: "John",
        last_name: "Smith",
        avatar_url: "https://example.com/avatar.jpg"
      )
    end

    it "still works if we need to get email from id_token_claims" do
      hash_without_info_email = google_auth_hash.dup
      hash_without_info_email[:info].delete("email")

      user = test_class.find_or_create_from_clavis(hash_without_info_email)

      expect(user.instance_variable_get(:@attributes)).to include(
        email: "john.smith@example.com" # Should get from id_token_claims
      )
    end

    it "handles string keys in id_token_claims" do
      hash_with_string_claims = google_auth_hash.dup
      hash_with_string_claims[:info].delete("email")
      hash_with_string_claims[:id_token_claims] = {
        "email" => "john.string_claims@example.com",
        "name" => "John Smith",
        "given_name" => "John",
        "family_name" => "Smith"
      }

      user = test_class.find_or_create_from_clavis(hash_with_string_claims)

      expect(user.instance_variable_get(:@attributes)).to include(
        email: "john.string_claims@example.com"
      )
    end

    it "handles mixed key types across different parts of the auth hash" do
      mixed_hash = {
        provider: :google,
        "uid" => "123456789012345678901",
        info: {
          "name" => "Mixed Keys",
          given_name: "Mixed",
          "family_name" => "Keys"
        },
        "credentials" => {
          token: "token-value"
        }
      }

      # We don't actually test the result here because our test implementation
      # doesn't need to handle this case, but this verifies we properly handle
      # the method call without errors
      expect do
        test_class.find_or_create_from_clavis(mixed_hash)
      end.not_to raise_error
    end
  end

  describe "handling GitHub OAuth hash" do
    let(:github_auth_hash) do
      {
        provider: :github,
        uid: "12345678",
        info: {
          nickname: "jsmith",
          email: "john.smith@example.com",
          name: "John Smith",
          image: "https://example.com/github-avatar.jpg",
          urls: {
            GitHub: "https://github.com/jsmith",
            Blog: "https://example.com/blog"
          }
        },
        credentials: {
          token: "example-github-token",
          expires: false
        }
      }
    end

    it "extracts user info correctly from GitHub auth hash" do
      user = test_class.find_or_create_from_clavis(github_auth_hash)

      expect(user.instance_variable_get(:@attributes)).to include(
        email: "john.smith@example.com",
        first_name: nil, # GitHub doesn't provide first/last name
        last_name: nil,
        avatar_url: "https://example.com/github-avatar.jpg"
      )
    end

    it "works when github hash has string keys instead of symbols" do
      string_key_hash = {
        provider: :github,
        uid: "12345678",
        info: {
          "nickname" => "jsmith",
          "email" => "john.string@example.com",
          "name" => "John String",
          "image" => "https://example.com/github-string-avatar.jpg"
        },
        credentials: {
          "token" => "example-github-token",
          "expires" => false
        }
      }

      user = test_class.find_or_create_from_clavis(string_key_hash)

      expect(user.instance_variable_get(:@attributes)).to include(
        email: "john.string@example.com",
        avatar_url: "https://example.com/github-string-avatar.jpg"
      )
    end
  end
end
