# frozen_string_literal: true

module Clavis
  module Providers
    class Google < Base
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
        params = {
          response_type: "code",
          client_id: client_id,
          redirect_uri: redirect_uri,
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
