# frozen_string_literal: true

require "jwt"
require "base64"
require "openssl"

module Clavis
  module Providers
    class Apple < Base
      attr_reader :team_id, :key_id, :private_key, :private_key_path

      APPLE_AUTH_URL = "https://appleid.apple.com/auth/authorize"
      APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"

      def initialize(config = {})
        @team_id = config[:team_id] || ENV.fetch("APPLE_TEAM_ID", nil)
        @key_id = config[:key_id] || ENV.fetch("APPLE_KEY_ID", nil)
        @private_key = config[:private_key] || ENV.fetch("APPLE_PRIVATE_KEY", nil)
        @private_key_path = config[:private_key_path] || ENV.fetch("APPLE_PRIVATE_KEY_PATH", nil)

        config[:authorization_endpoint] = APPLE_AUTH_URL
        config[:token_endpoint] = APPLE_TOKEN_URL
        config[:userinfo_endpoint] = nil # Apple doesn't have a userinfo endpoint

        super
      end

      def authorization_endpoint
        APPLE_AUTH_URL
      end

      def token_endpoint
        APPLE_TOKEN_URL
      end

      def userinfo_endpoint
        nil # Apple does not have a userinfo endpoint
      end

      def default_scopes
        "name email"
      end

      def openid_provider?
        true
      end

      def refresh_token(_refresh_token)
        # As of 2023, Apple does not support refresh tokens
        raise Clavis::UnsupportedOperation, "Apple does not support refresh tokens"
      end

      # Using keyword arguments without expected_state to match the base class interface
      # but we don't use expected_state in this implementation
      def token_exchange(code:, **_kwargs)
        # Validate inputs
        raise Clavis::InvalidGrant unless Clavis::Security::InputValidator.valid_code?(code)

        params = {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: redirect_uri,
          client_id: client_id,
          client_secret: generate_client_secret
        }

        response = http_client.post(token_endpoint, params)

        handle_token_error_response(response) if response.status != 200

        parse_token_response(response)
      end

      def get_user_info(_access_token)
        # Apple does not have a userinfo endpoint; user info is in the ID token
        raise Clavis::UnsupportedOperation, "Apple does not have a userinfo endpoint"
      end

      protected

      def validate_configuration!
        super
        raise Clavis::MissingConfiguration, "team_id for Apple" if @team_id.nil? || @team_id.empty?
        raise Clavis::MissingConfiguration, "key_id for Apple" if @key_id.nil? || @key_id.empty?
        raise Clavis::MissingConfiguration, "private_key for Apple" if @private_key.nil? && @private_key_path.nil?
      end

      def generate_client_secret
        # Apple requires a JWT as the client secret
        return @client_secret if @client_secret

        begin
          # Get the private key content
          key_content = if @private_key
                          @private_key
                        elsif @private_key_path
                          File.read(@private_key_path)
                        else
                          raise Clavis::MissingConfiguration, "private_key or private_key_path for Apple provider"
                        end

          raise Clavis::MissingConfiguration, "team_id for Apple provider" unless team_id
          raise Clavis::MissingConfiguration, "key_id for Apple provider" unless key_id

          # Load the private key
          private_key = OpenSSL::PKey::EC.new(key_content)

          # Generate JWT header
          header = { kid: key_id, alg: "ES256" }

          # Current time for JWT claims
          now = Time.now.to_i

          # Generate JWT claims
          claims = {
            iss: team_id,
            iat: now,
            exp: now + (86_400 * 180), # 180 days
            aud: "https://appleid.apple.com",
            sub: client_id
          }

          # Create and sign the JWT
          jwt = JWT.encode(claims, private_key, "ES256", header)

          # Cache and return the client secret
          @client_secret = jwt
        rescue StandardError => e
          Clavis.logger.error("Error generating Apple client secret: #{e.message}")
          raise
        end
      end
    end
  end
end
