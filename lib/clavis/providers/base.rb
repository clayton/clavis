# frozen_string_literal: true

require "faraday"
require "json"
require "base64"
require "cgi"

module Clavis
  module Providers
    class Base
      attr_reader :client_id, :client_secret, :redirect_uri

      def initialize(config = {})
        @client_id = config[:client_id] ||
                     ENV["CLAVIS_#{provider_name.upcase}_CLIENT_ID"] ||
                     (defined?(Rails) && Rails.application.credentials.dig(:clavis, provider_name, :client_id))

        @client_secret = config[:client_secret] ||
                         ENV["CLAVIS_#{provider_name.upcase}_CLIENT_SECRET"] ||
                         (defined?(Rails) && Rails.application.credentials.dig(:clavis, provider_name, :client_secret))

        @redirect_uri = config[:redirect_uri]

        validate_configuration!
      end

      def provider_name
        self.class.name.split("::").last.downcase.to_sym
      end

      def redirect_uri
        # Enforce HTTPS for redirect URI
        Clavis::Security::HttpsEnforcer.enforce_https(@redirect_uri)
      end

      def authorize_url(state:, nonce:, scope: nil)
        params = {
          response_type: "code",
          client_id: client_id,
          redirect_uri: redirect_uri,
          scope: scope || default_scopes,
          state: state
        }

        # Add nonce for OIDC
        params[:nonce] = nonce if openid_scope?(scope || default_scopes)

        Clavis::Logging.log_authorization_request(provider_name, params)

        # Enforce HTTPS for authorization endpoint
        auth_url = "#{authorization_endpoint}?#{to_query(params)}"
        Clavis::Security::HttpsEnforcer.enforce_https(auth_url)
      end

      def token_exchange(code:, expected_state: nil)
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
        parse_token_response(response)
      end

      def refresh_token(refresh_token)
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
        parse_token_response(response)
      end

      def process_callback(code, expected_state = nil)
        tokens = token_exchange(code: code, expected_state: expected_state)

        # Get user info from ID token or userinfo endpoint
        if tokens[:id_token] && openid_provider?
          id_token_data = parse_id_token(tokens[:id_token])
          user_info = process_id_token_claims(id_token_data)
        else
          user_info = get_user_info(tokens[:access_token])
        end

        Clavis::Logging.log_authorization_callback(provider_name, true)

        {
          provider: provider_name.to_s,
          uid: user_info[:sub] || user_info[:id],
          info: user_info,
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
        return {} unless userinfo_endpoint

        response = http_client.get(userinfo_endpoint) do |req|
          req.headers["Authorization"] = "Bearer #{access_token}"
        end

        if response.status != 200
          Clavis::Logging.log_userinfo_request(provider_name, false)
          handle_userinfo_error_response(response)
        end

        Clavis::Logging.log_userinfo_request(provider_name, true)
        response.body
      end

      def parse_id_token(token)
        # Basic JWT parsing without validation
        # In a real implementation, this would validate the token
        segments = token.split(".")

        raise Clavis::InvalidToken.new("Invalid JWT format") if segments.length != 3

        JSON.parse(Base64.urlsafe_decode64(segments[1]))
      rescue JSON::ParserError
        raise Clavis::InvalidToken.new("Invalid JWT payload")
      rescue ArgumentError
        raise Clavis::InvalidToken.new("Invalid JWT encoding")
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
        raise Clavis::MissingConfiguration.new("client_id for #{provider_name}") if @client_id.nil? || @client_id.empty?
        if @client_secret.nil? || @client_secret.empty?
          raise Clavis::MissingConfiguration.new("client_secret for #{provider_name}")
        end
        return unless @redirect_uri.nil? || @redirect_uri.empty?

        raise Clavis::MissingConfiguration.new("redirect_uri for #{provider_name}")
      end

      def http_client
        # Use the HTTPS enforcer to create a secure HTTP client
        Clavis::Security::HttpsEnforcer.create_http_client
      end

      def parse_token_response(response)
        data = JSON.parse(response.body, symbolize_names: true)

        {
          access_token: data[:access_token],
          token_type: data[:token_type],
          expires_in: data[:expires_in],
          refresh_token: data[:refresh_token],
          id_token: data[:id_token],
          expires_at: data[:expires_in] ? Time.now.to_i + data[:expires_in].to_i : nil
        }
      end

      def handle_token_error_response(response)
        raise Clavis::ProviderAPIError.new(provider_name, "HTTP #{response.status}") unless response.status == 400

        begin
          error_data = JSON.parse(response.body)
          error_code = error_data["error"]

          case error_code
          when "invalid_grant"
            raise Clavis::InvalidGrant.new(error_data["error_description"])
          when "invalid_client"
            raise Clavis::ConfigurationError.new("Invalid client credentials")
          else
            raise Clavis::TokenError.new(error_data["error_description"])
          end
        rescue JSON::ParserError
          raise Clavis::TokenError.new("Invalid response from token endpoint")
        end
      end

      def process_userinfo_response(response)
        JSON.parse(response.body, symbolize_names: true)
      end

      def process_id_token_claims(claims)
        {
          sub: claims["sub"],
          name: claims["name"],
          email: claims["email"],
          email_verified: claims["email_verified"],
          given_name: claims["given_name"],
          family_name: claims["family_name"],
          picture: claims["picture"]
        }
      end

      def openid_scope?(scope)
        scope.to_s.split(" ").include?("openid")
      end

      def to_query(params)
        params.map { |k, v| "#{k}=#{CGI.escape(v.to_s)}" }.join("&")
      end
    end
  end
end
