# frozen_string_literal: true

require "jwt"
require "base64"
require "openssl"

module Clavis
  module Providers
    class Apple < Base
      def authorization_endpoint
        "https://appleid.apple.com/auth/authorize"
      end

      def token_endpoint
        "https://appleid.apple.com/auth/token"
      end

      def userinfo_endpoint
        # Apple doesn't have a userinfo endpoint
        # User info is included in the ID token
        nil
      end

      def default_scopes
        "name email"
      end

      def openid_provider?
        true
      end

      def token_exchange(code:, expected_state: nil)
        # Apple requires a client_secret that is a JWT token
        params = {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: redirect_uri,
          client_id: client_id,
          client_secret: generate_client_secret
        }

        response = http_client.post(token_endpoint, params)

        if response.status != 200
          Clavis::Logging.log_token_exchange(provider_name, false)
          handle_token_error_response(response)
        end

        Clavis::Logging.log_token_exchange(provider_name, true)
        parse_token_response(response)
      end

      protected

      def process_id_token_claims(claims)
        # Apple includes user info in the ID token
        {
          sub: claims["sub"],
          email: claims["email"],
          email_verified: claims["email_verified"],
          name: claims["name"] || claims["email"]&.split("@")&.first
        }
      end

      def get_user_info(_access_token)
        # Apple doesn't have a userinfo endpoint
        # Return an empty hash, as user info is extracted from the ID token
        {}
      end

      private

      def generate_client_secret
        # Apple requires a JWT token as the client_secret
        # This is a simplified implementation
        # In a real app, you would need to:
        # 1. Get the private key from Apple Developer account
        # 2. Create a JWT token with the required claims

        # Check if a private key is provided in the configuration
        private_key_path = @config[:private_key_path]
        private_key_content = @config[:private_key]
        team_id = @config[:team_id]
        key_id = @config[:key_id]

        unless private_key_content || (private_key_path && File.exist?(private_key_path))
          raise Clavis::MissingConfiguration.new("private_key or private_key_path for Apple provider")
        end

        raise Clavis::MissingConfiguration.new("team_id for Apple provider") unless team_id

        raise Clavis::MissingConfiguration.new("key_id for Apple provider") unless key_id

        # Load the private key
        private_key = OpenSSL::PKey::EC.new(private_key_content || File.read(private_key_path))

        # Create the JWT token
        payload = {
          iss: team_id,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 86_400 * 180, # 180 days
          aud: "https://appleid.apple.com",
          sub: client_id
        }

        header = {
          kid: key_id,
          alg: "ES256"
        }

        JWT.encode(payload, private_key, "ES256", header)
      end
    end
  end
end
