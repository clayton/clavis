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
        "https://openidconnect.googleapis.com/v1/userinfo"
      end

      def default_scopes
        "openid email profile"
      end

      def openid_provider?
        true
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
