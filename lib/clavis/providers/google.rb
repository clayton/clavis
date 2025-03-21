# frozen_string_literal: true

require "jwt"
require "faraday"
require "json"

module Clavis
  module Providers
    class Google < Base
      ALLOWED_ISSUERS = ["accounts.google.com", "https://accounts.google.com"].freeze

      def initialize(config = {})
        # Validate required fields first
        if config[:client_id].nil? || config[:client_id].empty?
          raise Clavis::MissingConfiguration,
                "client_id for google"
        end
        if config[:client_secret].nil? || config[:client_secret].empty?
          raise Clavis::MissingConfiguration,
                "client_secret for google"
        end
        if config[:redirect_uri].nil? || config[:redirect_uri].empty?
          raise Clavis::MissingConfiguration,
                "redirect_uri for google"
        end

        # Set endpoints
        config[:authorization_endpoint] = "https://accounts.google.com/o/oauth2/v2/auth"
        config[:token_endpoint] = "https://oauth2.googleapis.com/token"
        config[:userinfo_endpoint] = "https://www.googleapis.com/oauth2/v3/userinfo"
        config[:scope] = config[:scope] || "openid email profile"

        # Set configurable options with defaults
        @jwt_leeway = config[:jwt_leeway] || 60
        @token_verification_enabled = config[:verify_tokens] != false
        @hosted_domain = config[:hosted_domain]
        @allowed_hosted_domains = Array(@hosted_domain) if @hosted_domain

        super
      end

      def authorization_endpoint
        "https://accounts.google.com/o/oauth2/v2/auth"
      end

      def token_endpoint
        "https://oauth2.googleapis.com/token"
      end

      def userinfo_endpoint
        "https://www.googleapis.com/oauth2/v3/userinfo"
      end

      def tokeninfo_endpoint
        "https://www.googleapis.com/oauth2/v3/tokeninfo"
      end

      def default_scopes
        "openid email profile"
      end

      def openid_provider?
        true
      end

      # Enhanced scope handling inspired by OmniAuth
      def normalize_scopes(scope_string)
        return default_scopes if scope_string.nil? || scope_string.empty?

        # Handle both space and comma-delimited scopes
        scopes = scope_string.split(/[\s,]+/)

        # Add default base scopes if not explicitly included
        base_scopes = %w[openid email profile]
        base_scopes.each do |base_scope|
          scopes << base_scope unless scopes.include?(base_scope)
        end

        scopes.uniq.join(" ")
      end

      def authorize_url(state:, nonce:, scope: nil, login_hint: nil, prompt: nil)
        # Validate state and nonce
        raise Clavis::InvalidState unless Clavis::Security::InputValidator.valid_state?(state)
        raise Clavis::InvalidNonce unless Clavis::Security::InputValidator.valid_state?(nonce)

        # Build authorization URL
        params = {
          response_type: "code",
          client_id: client_id,
          redirect_uri: Clavis::Security::HttpsEnforcer.enforce_https(redirect_uri),
          scope: normalize_scopes(scope || default_scopes),
          state: state,
          nonce: nonce,
          access_type: "offline"
        }

        # Add optional parameters if provided
        params[:login_hint] = login_hint if login_hint
        params[:prompt] = prompt || "consent" # Default to consent to ensure refresh token
        params[:hd] = @hosted_domain if @hosted_domain && @hosted_domain != "*"

        Clavis::Logging.log_authorization_request(provider_name, params)

        "#{authorization_endpoint}?#{to_query(params)}"
      end

      # Verify ID token with more comprehensive checks
      def verify_id_token(id_token)
        return {} if id_token.nil? || id_token.empty?

        begin
          # Decode without verification first to get the header and payload
          decoded_segments = ::JWT.decode(id_token, nil, false)
          decoded = decoded_segments.first

          # Now verify claims
          validate_id_token_claims!(decoded)

          decoded
        rescue ::JWT::DecodeError => e
          Clavis::Logging.log_token_verification(provider_name, false, "JWT decode error: #{e.message}")
          raise Clavis::InvalidToken, "Invalid ID token format"
        rescue StandardError => e
          Clavis::Logging.log_token_verification(provider_name, false, "Token verification error: #{e.message}")
          raise Clavis::InvalidToken, "ID token verification failed"
        end
      end

      def verify_token(access_token)
        return false unless @token_verification_enabled

        # Extract the token string from the access_token parameter
        token_str = case access_token
                    when Hash
                      token_val = access_token[:access_token] || access_token["access_token"]
                      token_val
                    when String
                      access_token
                    else
                      access_token.to_s
                    end

        return false if token_str.nil? || token_str.empty?

        begin
          response = http_client.get(tokeninfo_endpoint) do |req|
            req.params[:access_token] = token_str
          end

          # If status is not 200, we can immediately return false without parsing the body
          if response.status != 200
            Clavis::Logging.log_token_verification(provider_name, false, "Token info response: #{response.status}")
            return false
          end

          # Process response body based on what Faraday gives us
          token_info = {}

          # Faraday's response.body could be a Hash (with JSON middleware) or a String
          if response.body.is_a?(Hash)
            # Symbolize keys for consistency
            token_info = response.body.transform_keys(&:to_sym)
          elsif response.body.is_a?(String) && !response.body.empty?
            begin
              token_info = JSON.parse(response.body, symbolize_names: true)
            rescue JSON::ParserError
              Clavis::Logging.log_token_verification(provider_name, false, "Invalid JSON response")
              return false
            end
          else
            return false
          end

          # Verify the audience matches our client_id
          if token_info[:aud] != client_id
            Clavis::Logging.log_token_verification(provider_name, false, "Token audience mismatch")
            return false
          end

          # If we get here, the token is valid
          Clavis::Logging.log_token_verification(provider_name, true)
          true
        rescue StandardError => e
          Clavis::Logging.log_token_verification(provider_name, false, e.message)
          false
        end
      end

      # Verify hosted domain if configured
      def verify_hosted_domain(user_info)
        return true unless @hosted_domain
        return true if @hosted_domain == "*"

        user_hd = user_info[:hd]

        if user_hd.nil? || !@allowed_hosted_domains.include?(user_hd)
          Clavis::Logging.log_hosted_domain_verification(provider_name, false,
                                                         "Expected #{@allowed_hosted_domains}, got #{user_hd}")
          raise Clavis::InvalidHostedDomain, "User is not a member of the allowed hosted domain"
        end

        Clavis::Logging.log_hosted_domain_verification(provider_name, true)
        true
      end

      # Override to add token verification
      def get_user_info(access_token)
        # Extract the token string from the access_token parameter
        token_str = case access_token
                    when Hash
                      token_val = access_token[:access_token] || access_token["access_token"]
                      token_val
                    when String
                      access_token
                    else
                      access_token.to_s
                    end

        # Validate the access token if token verification is enabled
        if @token_verification_enabled
          verified = verify_token(access_token)
          raise Clavis::InvalidToken, "Access token verification failed" unless verified
        end

        # Get the user info from the Google API
        user_info = super(token_str)

        # Verify the hosted domain if configured
        verify_hosted_domain(user_info) if user_info && !user_info.empty?

        user_info || {}
      end

      protected

      def additional_authorize_params
        {
          access_type: "offline",
          prompt: "consent" # Force consent screen to ensure refresh token
        }
      end

      def process_userinfo_response(response)
        data = JSON.parse(response.body, symbolize_names: true)

        # For Google, we ALWAYS want to use the sub as the identifier
        {
          sub: data[:sub],
          email: data[:email],
          email_verified: data[:email_verified],
          name: data[:name],
          given_name: data[:given_name],
          family_name: data[:family_name],
          picture: data[:picture],
          hd: data[:hd] # Include hosted domain for verification
        }
      end

      def validate_id_token_claims!(payload)
        # Check issuer
        raise Clavis::InvalidToken, "Invalid issuer: #{payload["iss"]}" unless ALLOWED_ISSUERS.include?(payload["iss"])

        # Check audience
        raise Clavis::InvalidToken, "Invalid audience: #{payload["aud"]}" unless payload["aud"] == client_id

        # Check expiration with leeway
        exp_time = Time.at(payload["exp"].to_i)
        raise Clavis::InvalidToken, "Token expired at #{exp_time}" if Time.now > (exp_time + @jwt_leeway)

        # Check not before with leeway (if present)
        if payload["nbf"]
          nbf_time = Time.at(payload["nbf"].to_i)
          raise Clavis::InvalidToken, "Token not valid before #{nbf_time}" if Time.now < (nbf_time - @jwt_leeway)
        end

        true
      end
    end
  end
end
