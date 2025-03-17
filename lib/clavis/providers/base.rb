# frozen_string_literal: true

require "faraday"
require "json"
require "base64"
require "cgi"
require "uri"

module Clavis
  module Providers
    class Base
      attr_reader :client_id, :client_secret, :redirect_uri, :authorize_endpoint_url,
                  :token_endpoint_url, :userinfo_endpoint_url, :scope, :provider_name

      def initialize(config = {})
        @provider_name = self.class.name.split("::").last.downcase.to_sym
        @client_id = config[:client_id] ||
                     ENV["#{provider_name.to_s.upcase}_CLIENT_ID"] ||
                     (Clavis.configuration.use_rails_credentials ? fetch_from_credentials(:client_id) : nil)

        @client_secret = config[:client_secret] ||
                         ENV["#{provider_name.to_s.upcase}_CLIENT_SECRET"] ||
                         (Clavis.configuration.use_rails_credentials ? fetch_from_credentials(:client_secret) : nil)

        @redirect_uri = config[:redirect_uri] ||
                        ENV["#{provider_name.to_s.upcase}_REDIRECT_URI"] ||
                        (Clavis.configuration.use_rails_credentials ? fetch_from_credentials(:redirect_uri) : nil)

        @scope = config[:scope] || "email profile"

        setup_endpoints(config)
        validate_configuration!
      end

      def provider_name
        self.class.name.split("::").last.downcase.to_sym
      end

      def authorize_url(state:, nonce:, scope: nil)
        # Validate state and nonce
        raise Clavis::InvalidState unless Clavis::Security::InputValidator.valid_state?(state)
        raise Clavis::InvalidNonce unless Clavis::Security::InputValidator.valid_state?(nonce)

        # Build authorization URL
        uri = URI.parse(authorize_endpoint_url)
        params = {
          client_id: client_id,
          redirect_uri: Clavis::Security::HttpsEnforcer.enforce_https(redirect_uri),
          response_type: "code",
          state: state,
          nonce: nonce,
          scope: scope || @scope
        }

        # Add provider-specific params
        params.merge!(additional_authorize_params)

        # Encode and append params to the URL
        uri.query = URI.encode_www_form(params)
        uri.to_s
      end

      def token_exchange(code:, expected_state: nil)
        # Validate inputs
        raise Clavis::InvalidGrant unless Clavis::Security::InputValidator.valid_code?(code)

        raise Clavis::InvalidState if expected_state && !Clavis::Security::InputValidator.valid_state?(expected_state)

        params = {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: redirect_uri,
          client_id: client_id,
          client_secret: client_secret
        }

        response = http_client.post(token_endpoint_url, params)

        if response.status != 200
          Clavis::Logging.log_token_exchange(provider_name, false)
          handle_token_error_response(response)
        end

        Clavis::Logging.log_token_exchange(provider_name, true)

        # Parse and validate the token response
        token_data = parse_token_response(response)

        unless Clavis::Security::InputValidator.valid_token_response?(token_data)
          raise Clavis::InvalidToken, "Invalid token response format"
        end

        # Sanitize the token data to prevent XSS
        Clavis::Security::InputValidator.sanitize_hash(token_data)
      end

      def refresh_token(refresh_token)
        # Validate inputs
        raise Clavis::InvalidToken unless Clavis::Security::InputValidator.valid_token?(refresh_token)

        params = {
          grant_type: "refresh_token",
          refresh_token: refresh_token,
          client_id: client_id,
          client_secret: client_secret
        }

        response = http_client.post(token_endpoint_url, params)

        if response.status != 200
          Clavis::Logging.log_token_refresh(provider_name, false)
          handle_token_error_response(response)
        end

        Clavis::Logging.log_token_refresh(provider_name, true)

        # Parse and validate the token response
        token_data = parse_token_response(response)

        unless Clavis::Security::InputValidator.valid_token_response?(token_data)
          raise Clavis::InvalidToken, "Invalid token response format"
        end

        # Sanitize the token data to prevent XSS
        Clavis::Security::InputValidator.sanitize_hash(token_data)
      end

      def process_callback(code, expected_state = nil)
        # Validate inputs
        raise Clavis::InvalidGrant unless Clavis::Security::InputValidator.valid_code?(code)

        tokens = token_exchange(code: code, expected_state: expected_state)

        # Get user info from ID token or userinfo endpoint
        if tokens[:id_token] && openid_provider?
          id_token_data = parse_id_token(tokens[:id_token])
          user_info = process_id_token_claims(id_token_data)
        else
          user_info = get_user_info(tokens[:access_token])
        end

        # Validate the user info
        unless user_info.is_a?(Hash) && (user_info[:sub] || user_info[:id] || user_info["sub"] || user_info["id"])
          raise Clavis::InvalidToken, "Invalid user info format"
        end

        Clavis::Logging.log_authorization_callback(provider_name, true)

        # Sanitize all data to prevent XSS
        sanitized_user_info = Clavis::Security::InputValidator.sanitize_hash(user_info)

        {
          provider: provider_name.to_s,
          uid: sanitized_user_info[:sub] ||
            sanitized_user_info[:id] ||
            sanitized_user_info["sub"] ||
            sanitized_user_info["id"],
          info: sanitized_user_info,
          credentials: {
            token: tokens[:access_token],
            refresh_token: tokens[:refresh_token],
            expires_at: tokens[:expires_at],
            expires: tokens[:expires_at].present?
          },
          id_token: tokens[:id_token],
          id_token_claims: id_token_data
        }
      end

      def get_user_info(access_token)
        return {} unless userinfo_endpoint_url

        # Validate inputs
        raise Clavis::InvalidToken unless Clavis::Security::InputValidator.valid_token?(access_token)

        response = http_client.get(userinfo_endpoint_url) do |req|
          req.headers["Authorization"] = "Bearer #{access_token}"
        end

        if response.status != 200
          Clavis::Logging.log_userinfo_request(provider_name, false)
          handle_userinfo_error_response(response)
        end

        Clavis::Logging.log_userinfo_request(provider_name, true)

        # Validate and sanitize the response
        user_info = response.body

        unless Clavis::Security::InputValidator.valid_userinfo_response?(user_info)
          raise Clavis::InvalidToken, "Invalid user info format"
        end

        Clavis::Security::InputValidator.sanitize_hash(user_info)
      end

      def parse_id_token(id_token)
        # Validate the ID token
        raise Clavis::InvalidToken unless Clavis::Security::InputValidator.valid_token?(id_token)

        # Basic JWT parsing (without validation)
        parts = id_token.split(".")
        return {} if parts.length < 2

        begin
          json = Base64.urlsafe_decode64(parts[1] + ("=" * ((4 - (parts[1].length % 4)) % 4)))
          claims = JSON.parse(json)

          # Sanitize the claims to prevent XSS
          Clavis::Security::InputValidator.sanitize_hash(claims)
        rescue StandardError
          {}
        end
      end

      # These methods should be implemented by subclasses
      def authorization_endpoint
        raise NotImplementedError, "Subclasses must implement #authorization_endpoint"
      end

      def token_endpoint
        raise NotImplementedError, "Subclasses must implement #token_endpoint"
      end

      def userinfo_endpoint
        raise NotImplementedError, "Subclasses must implement #userinfo_endpoint"
      end

      def default_scopes
        Clavis.configuration.default_scopes || "email"
      end

      def openid_provider?
        false
      end

      protected

      def validate_configuration!
        raise Clavis::MissingConfiguration, "client_id for #{provider_name}" if @client_id.nil? || @client_id.empty?
        if @client_secret.nil? || @client_secret.empty?
          raise Clavis::MissingConfiguration, "client_secret for #{provider_name}"
        end
        return unless @redirect_uri.nil? || @redirect_uri.empty?

        raise Clavis::MissingConfiguration, "redirect_uri for #{provider_name}"
      end

      def http_client
        # Use the HTTPS enforcer to create a secure HTTP client
        Clavis::Security::HttpsEnforcer.create_http_client
      end

      def parse_token_response(response)
        data = response.body.is_a?(Hash) ? response.body : JSON.parse(response.body)

        {
          access_token: data["access_token"],
          token_type: data["token_type"],
          expires_in: data["expires_in"],
          refresh_token: data["refresh_token"],
          id_token: data["id_token"],
          expires_at: data["expires_in"] ? Time.now.to_i + data["expires_in"].to_i : nil
        }
      end

      def handle_token_error_response(response)
        data = response.body.is_a?(Hash) ? response.body : JSON.parse(response.body)

        error = data["error"] || "unknown_error"
        error_description = data["error_description"] || "Unknown error"

        case error
        when "invalid_request", "invalid_grant"
          raise Clavis::InvalidGrant, error_description
        when "invalid_client"
          raise Clavis::ProviderError.new(provider_name, "Invalid client credentials: #{error_description}")
        when "unauthorized_client"
          raise Clavis::ProviderError.new(provider_name, "Unauthorized client: #{error_description}")
        when "unsupported_grant_type"
          raise Clavis::UnsupportedOperation, error_description
        when "invalid_scope"
          raise Clavis::ProviderError.new(provider_name, "Invalid scope: #{error_description}")
        else
          raise Clavis::ProviderError.new(provider_name, "#{error}: #{error_description}")
        end
      end

      def handle_userinfo_error_response(_response)
        raise Clavis::InvalidAccessToken
      end

      def process_id_token_claims(claims)
        {
          sub: claims["sub"],
          email: claims["email"],
          email_verified: claims["email_verified"],
          name: claims["name"],
          given_name: claims["given_name"],
          family_name: claims["family_name"],
          picture: claims["picture"]
        }.compact
      end

      def openid_scope?(scope)
        scope.to_s.split.include?("openid")
      end

      def to_query(params)
        params.map { |k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}" }.join("&")
      end

      def setup_endpoints(config)
        @authorize_endpoint_url = config[:authorize_endpoint] || authorization_endpoint
        @token_endpoint_url = config[:token_endpoint] || token_endpoint
        @userinfo_endpoint_url = config[:userinfo_endpoint] || userinfo_endpoint
      end

      def additional_authorize_params
        {}
      end
    end
  end
end
