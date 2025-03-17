# frozen_string_literal: true

module Clavis
  module Providers
    class Google < Base
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

      def default_scopes
        "openid email profile"
      end

      def openid_provider?
        true
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
          state: state,
          nonce: nonce,
          access_type: "offline",
          prompt: "consent" # Force consent screen to ensure refresh token
        }

        Clavis::Logging.log_authorization_request(provider_name, params)

        "#{authorization_endpoint}?#{to_query(params)}"
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
        {
          sub: data[:sub],
          email: data[:email],
          email_verified: data[:email_verified],
          name: data[:name],
          given_name: data[:given_name],
          family_name: data[:family_name],
          picture: data[:picture]
        }
      end
    end
  end
end
