# frozen_string_literal: true

module Clavis
  module Providers
    class Microsoft < Base
      def initialize(config = {})
        @tenant = config[:tenant] || "common"

        # Set endpoints based on tenant
        config[:authorization_endpoint] = "https://login.microsoftonline.com/#{@tenant}/oauth2/v2.0/authorize"
        config[:token_endpoint] = "https://login.microsoftonline.com/#{@tenant}/oauth2/v2.0/token"
        config[:userinfo_endpoint] = "https://graph.microsoft.com/v1.0/me"
        config[:scope] = config[:scope] || "openid email profile User.Read"

        super
      end

      def authorization_endpoint
        "https://login.microsoftonline.com/#{tenant}/oauth2/v2.0/authorize"
      end

      def token_endpoint
        "https://login.microsoftonline.com/#{tenant}/oauth2/v2.0/token"
      end

      def userinfo_endpoint
        "https://graph.microsoft.com/v1.0/me"
      end

      def default_scopes
        "openid email profile User.Read"
      end

      def openid_provider?
        true
      end

      protected

      def process_userinfo_response(response)
        data = JSON.parse(response.body, symbolize_names: true)

        {
          sub: data[:id],
          name: data[:displayName],
          email: data[:mail] || data[:userPrincipalName],
          given_name: data[:givenName],
          family_name: data[:surname]
        }
      end

      private

      attr_reader :tenant
    end
  end
end
