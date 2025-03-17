# frozen_string_literal: true

module Clavis
  module Providers
    # Generic provider that can be used as a template for custom providers
    # This class requires all OAuth endpoints to be provided in the configuration
    class Generic < Base
      attr_reader :auth_endpoint, :token_endpoint_url, :userinfo_endpoint_url, :scopes

      def initialize(config = {})
        @auth_endpoint = config[:authorization_endpoint]
        @token_endpoint_url = config[:token_endpoint]
        @userinfo_endpoint_url = config[:userinfo_endpoint]
        @scopes = config[:scopes]
        @is_openid = config[:openid_provider] || false

        validate_endpoints!
        super
      end

      def authorization_endpoint
        @auth_endpoint
      end

      def token_endpoint
        @token_endpoint_url
      end

      def userinfo_endpoint
        @userinfo_endpoint_url
      end

      def default_scopes
        @scopes || ""
      end

      def openid_provider?
        @is_openid
      end

      protected

      def validate_endpoints!
        raise Clavis::MissingConfiguration, "authorization_endpoint" if @auth_endpoint.nil? || @auth_endpoint.empty?
        raise Clavis::MissingConfiguration, "token_endpoint" if @token_endpoint_url.nil? || @token_endpoint_url.empty?
        return unless @userinfo_endpoint_url.nil? || @userinfo_endpoint_url.empty?

        raise Clavis::MissingConfiguration, "userinfo_endpoint"
      end
    end
  end
end
