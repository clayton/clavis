# frozen_string_literal: true

module Clavis
  module Providers
    # Generic provider that can be used as a template for custom providers
    # This class requires all OAuth endpoints to be provided in the configuration
    class Generic < Base
      attr_reader :authorize_endpoint_url, :token_endpoint_url, :userinfo_endpoint_url

      def initialize(config = {})
        # Validation happens first
        validate_endpoints_config!(config)

        # These class vars will be derived from config, since we pass it all to super
        @is_openid = config[:openid_provider] || false

        # Support both :scope and :scopes for backward compatibility
        config[:scope] ||= config[:scopes] if config[:scopes]

        # Set provider_name explicitly for generic provider
        config[:provider_name] = :generic

        super
      end

      def authorization_endpoint
        @authorize_endpoint_url
      end

      def token_endpoint
        @token_endpoint_url
      end

      def userinfo_endpoint
        @userinfo_endpoint_url
      end

      def default_scopes
        @scope || ""
      end

      def openid_provider?
        @is_openid
      end

      protected

      def validate_endpoints_config!(config)
        if config[:authorization_endpoint].nil? || config[:authorization_endpoint].empty?
          raise Clavis::MissingConfiguration,
                "authorization_endpoint"
        end
        if config[:token_endpoint].nil? || config[:token_endpoint].empty?
          raise Clavis::MissingConfiguration,
                "token_endpoint"
        end
        return unless config[:userinfo_endpoint].nil? || config[:userinfo_endpoint].empty?

        raise Clavis::MissingConfiguration, "userinfo_endpoint"
      end
    end
  end
end
