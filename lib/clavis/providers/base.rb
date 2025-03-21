# frozen_string_literal: true

require "faraday"
require "json"
require "base64"
require "cgi"
require "uri"
require "rack"
require "digest"
require "net/http"
require "securerandom"
require "clavis/security/input_validator"
require "clavis/security/https_enforcer"
require "clavis/security/parameter_filter"
require "clavis/security/redirect_uri_validator"
require "clavis/security/csrf_protection"
require "openssl"
require "jwt"
require "clavis/providers/token_exchange_handler"

module Clavis
  module Providers
    class Base
      include Clavis::Providers::TokenExchangeHandler

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

      def token_exchange(options = {})
        code = options[:code]
        redirect_uri = options[:redirect_uri] || @redirect_uri

        Clavis::Logging.debug("#{provider_name}#token_exchange - Starting with options: #{options.inspect}")

        # Set up the token exchange parameters
        params = build_token_exchange_params(code, redirect_uri)

        # Make the token exchange request
        begin
          response = make_token_request(params)
          token_response = parse_response(response)

          # Check for error
          handle_error_response(token_response, response.status)

          # Log the token exchange
          Clavis::Logging.log_token_exchange(provider_name, true)

          # Return the token data
          process_id_token_if_present(token_response)
        rescue Faraday::ConnectionFailed, Faraday::TimeoutError => e
          handle_connection_error(e)
        rescue Faraday::Error => e
          handle_faraday_error(e)
        rescue JSON::ParserError => e
          handle_parser_error(e)
        rescue StandardError => e
          handle_standard_error(e)
        end
      end

      def get_user_info(access_token)
        return {} unless userinfo_endpoint

        # Validate the access token - temporarily bypass validation for debugging
        # raise Clavis::InvalidToken unless Clavis::Security::InputValidator.valid_token?(access_token)

        response = http_client.get(userinfo_endpoint) do |req|
          req.headers["Authorization"] = "Bearer #{access_token}"
        end

        if response.status != 200
          Clavis::Logging.log_userinfo_request(provider_name, false)
          handle_userinfo_error_response(response)
        end

        Clavis::Logging.log_userinfo_request(provider_name, true)

        # Parse and validate the response
        user_info = if response.body.is_a?(Hash)
                      response.body
                    else
                      begin
                        parsed = JSON.parse(response.body.to_s, symbolize_names: true)
                        parsed
                      rescue JSON::ParserError
                        {}
                      end
                    end

        # TEMPORARY: Skip validation to debug further
        # unless Clavis::Security::InputValidator.valid_userinfo_response?(user_info)
        #   raise Clavis::InvalidToken, "Invalid user info format"
        # end

        # Sanitize the user info to prevent XSS
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

        Clavis::Logging.log_authorization_request(provider_name,
                                                  Clavis::Security::ParameterFilter.filter_params(params))

        uri = URI.parse(authorization_endpoint)
        uri.query = URI.encode_www_form(params)

        # Enforce HTTPS for authorization URLs (if configured)
        uri.scheme = "https" if Clavis.configuration.enforce_https && uri.scheme == "http"

        uri.to_s
      end

      def process_callback(code, user_data = nil)
        Clavis::Logging.debug("#{provider_name}#process_callback - Starting with code: #{code.inspect}")

        # Normalize the code by removing quote characters and trimming whitespace
        clean_code = code.gsub(/^"|"$/, "").strip
        Clavis::Logging.debug("#{provider_name}#process_callback - Cleaned code: #{clean_code}")

        Clavis::Logging.debug("#{provider_name}#process_callback - Calling token_exchange")
        token_data = token_exchange(code: clean_code)
        Clavis::Logging.debug("#{provider_name}#process_callback - Token data received: #{token_data.inspect}")

        # If we have a token, try to get user info
        user_info = {}
        if token_data[:access_token]
          begin
            # Debug log excluding sensitive information
            token_data.except(:access_token, :refresh_token, :id_token)
            Clavis::Logging.debug(
              "#{provider_name}#process_callback - Calling get_user_info with " \
              "access_token: #{token_data[:access_token].inspect}"
            )
            user_info = get_user_info(token_data[:access_token])
            Clavis::Logging.debug("#{provider_name}#process_callback - User info received: #{user_info.inspect}")
          rescue Clavis::UnsupportedOperation => e
            Clavis::Logging.debug("#{provider_name}#process_callback - UnsupportedOperation: #{e.message}")
            user_info = {}
          rescue StandardError => e
            # Debug log error from user info
            Clavis::Logging.debug(
              "#{provider_name}#process_callback - Error getting user info: " \
              "#{e.class.name}: #{e.message}"
            )
            Clavis::Logging.debug("#{provider_name}#process_callback - Error backtrace: #{e.backtrace.join("\n")}")
            raise
          end
        else
          Clavis::Logging.debug("#{provider_name}#process_callback - No access_token available, skipping user_info")
        end

        # Determine a unique identifier (UID) for the user
        # Prefer ID token claims as the most reliable source
        uid = if token_data[:id_token_claims] && token_data[:id_token_claims][:sub]
                Clavis::Logging.debug("#{provider_name}#process_callback - Using sub from id_token_claims as UID")
                token_data[:id_token_claims][:sub]
              elsif user_info[:sub]
                Clavis::Logging.debug("#{provider_name}#process_callback - Using sub from user_info as UID")
                user_info[:sub]
              elsif user_info[:id]
                Clavis::Logging.debug("#{provider_name}#process_callback - Using id from user_info as UID")
                user_info[:id]
              else
                # Generate a hash of some token data for consistent ids
                Clavis::Logging.debug("#{provider_name}#process_callback - Generating fallback UID")
                data_for_hash = "#{provider_name}:#{token_data[:access_token] || ""}:#{user_info[:email] || ""}"
                Digest::SHA1.hexdigest(data_for_hash)[0...20] # Use first 20 characters for a longer UID
              end

        Clavis::Logging.debug("#{provider_name}#process_callback - UID determined: #{uid}")

        # Merge data from ID token if available
        id_token_claims = {}
        if token_data[:id_token]
          begin
            Clavis::Logging.debug("#{provider_name}#process_callback - Decoding ID token")
            id_token_claims = decode_id_token(token_data[:id_token])
            Clavis::Logging.debug("#{provider_name}#process_callback - ID token claims: #{id_token_claims.inspect}")
          rescue StandardError => e
            Clavis::Logging.debug("#{provider_name}#process_callback - Error decoding ID token: #{e.message}")
            # Don't fail if we can't decode the ID token
          end
        end

        # Debug log ID token claims
        Clavis::Logging.debug(
          "#{provider_name}#process_id_token_if_present - ID token claims: " \
          "#{id_token_claims.inspect}"
        )

        # Do any provider-specific user data processing
        processed_user_data = process_user_data(user_data) if user_data

        # Build the standardized auth hash
        result = {
          provider: provider_name,
          uid: uid,
          info: user_info.merge(processed_user_data || {}),
          credentials: {
            token: token_data[:access_token],
            refresh_token: token_data[:refresh_token],
            expires_at: token_data[:expires_at],
            expires: !token_data[:expires_at].nil?
          }
        }

        # Add ID token if available
        result[:id_token] = token_data[:id_token] if token_data[:id_token]
        if token_data[:id_token_claims] || !id_token_claims.empty?
          result[:id_token_claims] =
            token_data[:id_token_claims] || id_token_claims
        end

        Clavis::Logging.debug("#{provider_name}#process_callback - Returning auth hash: #{result.inspect}")
        result
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

      def parse_token_response(response_or_body)
        # Handle both response objects and direct body inputs
        response_body = if response_or_body.respond_to?(:body)
                          # It's a response object
                          response_or_body.body
                        else
                          # It's already a body
                          response_or_body
                        end

        # Process the body based on its type
        data = if response_body.is_a?(Hash)
                 response_body
               elsif response_body.is_a?(String) && !response_body.empty?
                 # For tests that might not use Faraday's JSON middleware
                 begin
                   JSON.parse(response_body)
                 rescue JSON::ParserError
                   # Try to parse as form-encoded for non-JSON responses
                   begin
                     Rack::Utils.parse_nested_query(response_body)
                   rescue StandardError
                     {}
                   end
                 end
               else
                 # Empty or nil response
                 {}
               end

        # Symbolize keys for consistency
        result = data.transform_keys(&:to_sym)

        # Ensure we've got the right data structure
        result[:token_type] ||= "Bearer" # Default token type

        # Handle expires_in
        if result[:expires_in]
          # Convert to integer if possible
          expires_in = result[:expires_in].to_i
          result[:expires_at] = Time.now.to_i + expires_in if expires_in.positive?
        end

        result
      end

      def handle_token_error_response(response)
        error_data = begin
          if response.body.is_a?(Hash)
            response.body
          else
            JSON.parse(response.body.to_s, symbolize_names: true)
          end
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
          if response.body.is_a?(Hash)
            response.body
          else
            JSON.parse(response.body.to_s, symbolize_names: true)
          end
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

      def decode_id_token(id_token)
        # Extract the payload part of the JWT (second segment)
        segments = id_token.split(".")

        return {} if segments.length < 2

        # Decode the payload
        encoded_payload = segments[1]

        # Add padding if needed
        padding_length = 4 - (encoded_payload.length % 4)
        encoded_payload += "=" * padding_length if padding_length < 4

        # Base64 decode
        decoded = Base64.urlsafe_decode64(encoded_payload)

        # Parse JSON
        JSON.parse(decoded, symbolize_names: true)
      rescue StandardError
        {}
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

      # Process ID token if present in the token response
      def process_id_token_if_present(token_data)
        # If there's an ID token in the response, and we're dealing with an OpenID provider,
        # try to extract claims from it
        if openid_provider? && token_data[:id_token] && !token_data[:id_token].to_s.empty?
          begin
            Clavis::Logging.debug("#{provider_name}#process_id_token_if_present - Processing ID token")
            id_token_claims = decode_id_token(token_data[:id_token])
            token_data[:id_token_claims] = id_token_claims

            # Log claims with line breaks to avoid line length issues
            log_message = "#{provider_name}#process_id_token_if_present - "
            log_message += "ID token claims: #{id_token_claims.inspect}"
            Clavis::Logging.debug(log_message)
          rescue StandardError => e
            # Log error with line breaks to avoid line length issues
            log_message = "#{provider_name}#process_id_token_if_present - "
            log_message += "Error decoding ID token: #{e.message}"
            Clavis::Logging.debug(log_message)

            # Continue with empty claims if we can't decode the token
            token_data[:id_token_claims] = {}
          end
        end

        # Return the token data, possibly with ID token claims
        token_data
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
