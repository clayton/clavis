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
                  :token_endpoint_url, :userinfo_endpoint_url, :scope

      def initialize(config = {})
        @config = config
        set_provider_name
        load_credentials
        setup_endpoints(config)
        validate_configuration!
      end

      # Get the provider name (e.g., :google, :github)
      attr_reader :provider_name

      # Abstract methods that should be implemented by subclasses
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
        @scope || Clavis.configuration.default_scopes || "email"
      end

      def openid_provider?
        false
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

        response = http_client.post(token_endpoint, params)

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

        response = http_client.post(token_endpoint, params)

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

      def get_user_info(access_token)
        return {} unless userinfo_endpoint

        # Validate inputs
        raise Clavis::InvalidToken unless Clavis::Security::InputValidator.valid_token?(access_token)

        response = http_client.get(userinfo_endpoint) do |req|
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

      def authorize_url(state:, nonce:, scope: nil)
        # Validate state and nonce
        raise Clavis::InvalidState unless Clavis::Security::InputValidator.valid_state?(state)
        raise Clavis::InvalidNonce unless Clavis::Security::InputValidator.valid_state?(nonce)

        # Build authorization URL
        params = {
          response_type: "code",
          client_id: client_id,
          redirect_uri: Clavis::Security::HttpsEnforcer.enforce_https(redirect_uri),
          scope: scope || default_scopes,
          state: state
        }

        # Add nonce for OpenID providers
        params[:nonce] = nonce if openid_provider?

        # Add provider-specific params
        params.merge!(additional_authorize_params)

        Clavis::Logging.log_authorization_request(provider_name, params)

        "#{authorization_endpoint}?#{to_query(params)}"
      end

      protected

      def setup_endpoints(config)
        @authorize_endpoint_url = config[:authorization_endpoint]
        @token_endpoint_url = config[:token_endpoint]
        @userinfo_endpoint_url = config[:userinfo_endpoint]
      end

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
        data = JSON.parse(response.body, symbolize_names: true)
        expires_at = data[:expires_in] ? Time.now.to_i + data[:expires_in].to_i : nil

        {
          access_token: data[:access_token],
          token_type: data[:token_type],
          expires_in: data[:expires_in],
          refresh_token: data[:refresh_token],
          expires_at: expires_at,
          id_token: data[:id_token]
        }.compact
      end

      def handle_token_error_response(response)
        error_data = begin
          JSON.parse(response.body, symbolize_names: true)
        rescue StandardError
          { error: "unknown_error" }
        end

        error_code = error_data[:error] || "server_error"
        error_description = error_data[:error_description] || "An error occurred"

        case error_code
        when "invalid_grant"
          # Use the error description from the response if available
          raise Clavis::InvalidGrant, (if error_description == "An error occurred"
                                         "The refresh token is invalid or has expired"
                                       else
                                         error_description
                                       end)
        when "invalid_client"
          raise Clavis::InvalidClient, "Invalid client credentials"
        when "unauthorized_client"
          raise Clavis::UnauthorizedClient, "The client is not authorized to use this grant type"
        when "unsupported_grant_type"
          raise Clavis::UnsupportedGrantType, "The grant type is not supported by the authorization server"
        when "invalid_scope"
          raise Clavis::InvalidScope, "The requested scope is invalid or unknown"
        else
          raise Clavis::OAuthError, "OAuth error: #{error_code}"
        end
      end

      def handle_userinfo_error_response(response)
        error_data = begin
          JSON.parse(response.body, symbolize_names: true)
        rescue StandardError
          { error: "unknown_error" }
        end
        error_code = error_data[:error] || "server_error"

        case error_code
        when "invalid_token"
          raise Clavis::InvalidToken, "The access token is invalid or has expired"
        when "insufficient_scope"
          raise Clavis::InsufficientScope, "The token does not have the required scopes"
        else
          raise Clavis::OAuthError, "OAuth error: #{error_code}"
        end
      end

      def additional_authorize_params
        {}
      end

      def to_query(params)
        params.map { |k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}" }.join("&")
      end

      def fetch_from_credentials(key)
        return nil unless defined?(Rails) && Rails.application.respond_to?(:credentials)

        Rails.application.credentials.dig(:clavis, :providers, provider_name, key)
      end

      private

      def set_provider_name
        @provider_name = if @config[:provider_name]
                           @config[:provider_name].to_sym
                         elsif self.class.name
                           self.class.name.split("::").last.downcase.to_sym
                         else
                           :generic # fallback for anonymous classes in tests
                         end
      end

      def load_credentials
        @client_id = @config[:client_id] ||
                     ENV["#{provider_name.to_s.upcase}_CLIENT_ID"] ||
                     (Clavis.configuration.use_rails_credentials ? fetch_from_credentials(:client_id) : nil)

        @client_secret = @config[:client_secret] ||
                         ENV["#{provider_name.to_s.upcase}_CLIENT_SECRET"] ||
                         (Clavis.configuration.use_rails_credentials ? fetch_from_credentials(:client_secret) : nil)

        @redirect_uri = @config[:redirect_uri] ||
                        ENV["#{provider_name.to_s.upcase}_REDIRECT_URI"] ||
                        (Clavis.configuration.use_rails_credentials ? fetch_from_credentials(:redirect_uri) : nil)

        @scope = @config[:scope] || "email profile"
      end
    end
  end
end
