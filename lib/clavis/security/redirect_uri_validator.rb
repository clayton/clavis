# frozen_string_literal: true

require "uri"

module Clavis
  module Security
    module RedirectUriValidator
      class << self
        # Validates a URI against the configured allowed hosts
        # @param uri [String] The URI to validate
        # @return [Boolean] Whether the URI is valid
        def valid_uri?(uri)
          return false if uri.nil? || uri.empty?

          begin
            parsed_uri = URI.parse(uri)

            # Check if localhost is allowed in development
            return allow_localhost_in_development? if localhost?(parsed_uri.host)

            # Check against allowed hosts
            return true if host_allowed?(parsed_uri.host)

            false
          rescue URI::InvalidURIError
            false
          end
        end

        # Validates a URI for a specific provider
        # @param provider_name [Symbol] The provider name
        # @param uri [String] The URI to validate
        # @return [Boolean] Whether the URI is valid for the provider
        def valid_provider_uri?(provider_name, uri)
          return false if uri.nil? || uri.empty?

          begin
            # First check if the URI is valid against allowed hosts
            return false unless valid_uri?(uri)

            # Get the configured redirect URI for the provider
            provider_config = Clavis.configuration.provider_config(provider_name)
            configured_uri = provider_config[:redirect_uri]

            return true if configured_uri.nil? # No specific URI configured

            parsed_uri = URI.parse(uri)
            parsed_configured_uri = URI.parse(configured_uri)

            # Check if exact matching is required
            return uri == configured_uri if Clavis.configuration.exact_redirect_uri_matching

            # Check if the host and path match
            parsed_uri.host == parsed_configured_uri.host &&
              parsed_uri.path == parsed_configured_uri.path
          rescue URI::InvalidURIError, Clavis::ProviderNotConfigured
            false
          end
        end

        # Validates a URI and raises an exception if invalid
        # @param uri [String] The URI to validate
        # @return [Boolean] Whether the URI is valid
        # @raise [Clavis::InvalidRedirectUri] If the URI is invalid and raise_on_invalid_redirect is true
        def validate_uri!(uri)
          is_valid = valid_uri?(uri)

          raise Clavis::InvalidRedirectUri, uri if !is_valid && Clavis.configuration.raise_on_invalid_redirect

          is_valid
        end

        # Validates a URI for a specific provider and raises an exception if invalid
        # @param provider_name [Symbol] The provider name
        # @param uri [String] The URI to validate
        # @return [Boolean] Whether the URI is valid for the provider
        # @raise [Clavis::InvalidRedirectUri] If the URI is invalid and raise_on_invalid_redirect is true
        def validate_provider_uri!(provider_name, uri)
          is_valid = valid_provider_uri?(provider_name, uri)

          raise Clavis::InvalidRedirectUri, uri if !is_valid && Clavis.configuration.raise_on_invalid_redirect

          is_valid
        end

        private

        # Checks if a host is localhost
        # @param host [String] The host to check
        # @return [Boolean] Whether the host is localhost
        def localhost?(host)
          ["localhost", "127.0.0.1"].include?(host)
        end

        # Checks if localhost is allowed in the current environment
        # @return [Boolean] Whether localhost is allowed
        def allow_localhost_in_development?
          return false unless Clavis.configuration.allow_localhost_in_development

          # If Rails is not defined, allow localhost in development mode
          return true unless defined?(Rails)

          # Allow localhost in development or test environments
          Rails.env.development? || Rails.env.test?
        end

        # Checks if a host is in the allowed hosts list
        # @param host [String] The host to check
        # @return [Boolean] Whether the host is allowed
        def host_allowed?(host)
          return false if host.nil?

          allowed_hosts = Clavis.configuration.allowed_redirect_hosts
          return false if allowed_hosts.empty?

          # Check if the host matches any allowed host or is a subdomain of an allowed host
          allowed_hosts.any? do |allowed_host|
            host == allowed_host || host.end_with?(".#{allowed_host}")
          end
        end
      end
    end
  end
end
