# frozen_string_literal: true

require "jwt"
require "base64"
require "openssl"
require "securerandom"
require "net/http"
require "json"

module Clavis
  module Providers
    class Apple < Base
      attr_reader :team_id, :key_id, :private_key, :private_key_path, :authorized_client_ids, :client_options

      ISSUER = "https://appleid.apple.com"
      APPLE_AUTH_URL = "#{ISSUER}/auth/authorize".freeze
      APPLE_TOKEN_URL = "#{ISSUER}/auth/token".freeze
      APPLE_JWKS_URL = "#{ISSUER}/auth/keys".freeze
      DEFAULT_CLIENT_SECRET_EXPIRY = 300 # 5 minutes in seconds

      def initialize(config = {})
        @team_id = config[:team_id] || ENV.fetch("APPLE_TEAM_ID", nil)
        @key_id = config[:key_id] || ENV.fetch("APPLE_KEY_ID", nil)
        @private_key = config[:private_key] || ENV.fetch("APPLE_PRIVATE_KEY", nil)
        @private_key_path = config[:private_key_path] || ENV.fetch("APPLE_PRIVATE_KEY_PATH", nil)
        @authorized_client_ids = config[:authorized_client_ids] || []
        @client_secret_expiry = config[:client_secret_expiry] || DEFAULT_CLIENT_SECRET_EXPIRY
        @client_options = config[:client_options] || {}

        # Set up endpoints with potential overrides from client_options
        endpoints = {
          authorization_endpoint: @client_options[:authorize_url] || APPLE_AUTH_URL,
          token_endpoint: @client_options[:token_url] || APPLE_TOKEN_URL,
          userinfo_endpoint: nil # Apple doesn't have a userinfo endpoint
        }

        # Override base URL if site is specified
        if @client_options[:site]
          base_uri = URI.parse(@client_options[:site])
          auth_uri = URI.parse(endpoints[:authorization_endpoint])
          token_uri = URI.parse(endpoints[:token_endpoint])

          # Only override the host, keep the paths
          auth_uri.scheme = base_uri.scheme
          auth_uri.host = base_uri.host
          token_uri.scheme = base_uri.scheme
          token_uri.host = base_uri.host

          endpoints[:authorization_endpoint] = auth_uri.to_s
          endpoints[:token_endpoint] = token_uri.to_s
        end

        config.merge!(endpoints)
        super
      end

      def authorization_endpoint
        @authorize_endpoint_url
      end

      def token_endpoint
        @token_endpoint_url
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
        # Apple doesn't support the standard OAuth refresh token flow
        # Instead, they use long-lived tokens that don't need refreshing
        raise Clavis::UnsupportedOperation, "Apple does not support refresh tokens"
      end

      # Using keyword arguments with support for state verification (for compatibility)
      def token_exchange(code:, **kwargs)
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

        token_data = parse_token_response(response)

        # If id_token is present, verify and extract claims
        if token_data[:id_token] && !token_data[:id_token].empty?
          begin
            token_data[:id_token_claims] = verify_and_decode_id_token(
              token_data[:id_token],
              kwargs[:nonce]
            )
          rescue StandardError => e
            Clavis.logger.warn("Failed to verify ID token: #{e.message}")
          end
        end

        # Process user data if available
        if kwargs[:user_data] && !kwargs[:user_data].empty?
          begin
            token_data[:user_info] = JSON.parse(kwargs[:user_data])
          rescue JSON::ParserError => e
            Clavis.logger.warn("Failed to parse user data: #{e.message}")
          end
        end

        token_data
      end

      def get_user_info(_access_token)
        # Apple does not have a userinfo endpoint; user info is in the ID token
        raise Clavis::UnsupportedOperation, "Apple does not have a userinfo endpoint"
      end

      def authorize_url(state:, nonce:, scope: nil)
        # Generate a more secure URL with form_post response mode
        params = {
          response_type: "code",
          client_id: client_id,
          redirect_uri: Clavis::Security::HttpsEnforcer.enforce_https(redirect_uri),
          scope: scope || default_scopes,
          state: state,
          nonce: nonce,
          response_mode: "form_post" # Required for getting user information
        }

        uri = URI.parse(authorization_endpoint)
        uri.query = URI.encode_www_form(params)

        # Enforce HTTPS
        uri.scheme = "https" if Clavis.configuration.enforce_https && uri.scheme == "http"

        uri.to_s
      end

      def process_callback(code, user_data = nil)
        clean_code = code.to_s.gsub(/\A["']|["']\Z/, "")
        token_data = token_exchange(code: clean_code, user_data: user_data)

        # Extract user info from id_token and/or user_data
        user_info = extract_user_info(token_data)

        # For OpenID Connect, use sub claim as identifier
        uid = if token_data[:id_token_claims]&.dig(:sub)
                token_data[:id_token_claims][:sub]
              else
                # Generate a hash as fallback
                data_for_hash = "#{provider_name}:#{token_data[:access_token] || ""}:#{user_info[:email] || ""}"
                Digest::SHA1.hexdigest(data_for_hash)[0..19]
              end

        {
          provider: provider_name,
          uid: uid,
          info: user_info,
          credentials: {
            token: token_data[:access_token],
            refresh_token: token_data[:refresh_token],
            expires_at: token_data[:expires_at],
            expires: token_data[:expires_at] && !token_data[:expires_at].nil?
          },
          id_token: token_data[:id_token],
          id_token_claims: token_data[:id_token_claims] || {}
        }
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
            exp: now + @client_secret_expiry,
            aud: ISSUER,
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

      def fetch_jwk(kid)
        uri = URI.parse(APPLE_JWKS_URL)

        begin
          response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
            http.open_timeout = 5
            http.read_timeout = 5
            http.get(uri.path)
          end

          return nil unless response.is_a?(Net::HTTPSuccess)

          jwks = JSON.parse(response.body)
          jwks["keys"].find { |key| key["kid"] == kid }
        rescue StandardError => e
          Clavis.logger.error("Error fetching Apple JWK: #{e.message}")
          nil
        end
      end

      def verify_and_decode_id_token(id_token, expected_nonce = nil)
        # Basic decode to get header and payload without verification
        segments = id_token.split(".")
        return {} if segments.length < 2

        # Decode header to get kid
        header_segment = segments[0]
        # Add padding if needed
        header_segment += "=" * ((4 - (header_segment.length % 4)) % 4)
        header_json = Base64.urlsafe_decode64(header_segment)
        header = JSON.parse(header_json)
        kid = header["kid"]

        # Decode payload for basic verification
        payload_segment = segments[1]
        # Add padding if needed
        payload_segment += "=" * ((4 - (payload_segment.length % 4)) % 4)
        payload_json = Base64.urlsafe_decode64(payload_segment)
        payload = JSON.parse(payload_json, symbolize_names: true)

        # Verify JWT claims
        verify_issuer(payload)
        verify_audience(payload)
        verify_expiration(payload)
        verify_issued_at(payload)
        verify_nonce(payload, expected_nonce) if expected_nonce

        # Optional: Verify signature with JWKS
        if kid
          jwk = fetch_jwk(kid)
          if jwk
            # Convert JWK to PEM format for verification
            Clavis.logger.info("JWT signature verification with JWK is not implemented yet")
            # Future implementation would verify the JWT signature here
          end
        end

        # Return the verified claims
        payload
      rescue StandardError => e
        Clavis.logger.error("ID token verification failed: #{e.message}")
        {}
      end

      def verify_issuer(payload)
        return if payload[:iss] == ISSUER

        raise Clavis::InvalidToken, "Invalid issuer: expected #{ISSUER}, got #{payload[:iss]}"
      end

      def verify_audience(payload)
        valid_audiences = [client_id] + authorized_client_ids
        return if valid_audiences.include?(payload[:aud])

        raise Clavis::InvalidToken, "Invalid audience: #{payload[:aud]}"
      end

      def verify_expiration(payload)
        return if payload[:exp] && payload[:exp] > Time.now.to_i

        raise Clavis::InvalidToken, "Token expired"
      end

      def verify_issued_at(payload)
        return if payload[:iat] && payload[:iat] <= Time.now.to_i

        raise Clavis::InvalidToken, "Invalid issued at time"
      end

      def verify_nonce(payload, expected_nonce)
        return if payload[:nonce] && payload[:nonce] == expected_nonce

        raise Clavis::InvalidToken, "Nonce mismatch"
      end

      def extract_user_info(token_data)
        info = {}

        # Extract from ID token claims (prioritized for security)
        if token_data[:id_token_claims]
          claims = token_data[:id_token_claims]
          info[:email] = claims[:email]
          info[:email_verified] = [true, "true"].include?(claims[:email_verified])
          info[:is_private_email] = [true, "true"].include?(claims[:is_private_email])
          info[:sub] = claims[:sub]
        end

        # Extract from user_info if available (comes from form_post)
        if token_data[:user_info]
          user_data = token_data[:user_info]
          if user_data["name"]
            info[:first_name] = user_data["name"]["firstName"]
            info[:last_name] = user_data["name"]["lastName"]
            # Combine name parts if available
            if info[:first_name] || info[:last_name]
              info[:name] = [info[:first_name], info[:last_name]].compact.join(" ")
            end
          end

          # Only use email from user_data if not already set from ID token
          # This prevents email spoofing attacks
          info[:email] ||= user_data["email"]
        end

        # If no name was set but we have email, use that as name
        info[:name] ||= info[:email]

        info
      end
    end
  end
end
