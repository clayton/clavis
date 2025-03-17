# frozen_string_literal: true

require "uri"
require "faraday"

module Clavis
  module Security
    module HttpsEnforcer
      class << self
        # Enforces HTTPS for a URL
        # @param url [String] The URL to enforce HTTPS for
        # @return [String] The URL with HTTPS enforced
        def enforce_https(url)
          return url unless Clavis.configuration.enforce_https
          return url if url.nil? || url.empty?

          begin
            uri = URI.parse(url)

            # Skip if already HTTPS
            return url if uri.scheme == "https"

            # Allow HTTP for localhost in development if configured
            if localhost?(uri.host) &&
               Clavis.configuration.allow_http_localhost &&
               (defined?(Rails) && !Rails.env.production?)
              return url
            end

            # Upgrade to HTTPS
            uri.scheme = "https"
            uri.to_s
          rescue URI::InvalidURIError
            url
          end
        end

        # Creates a new HTTP client with proper TLS configuration
        # @return [Faraday::Connection] A configured HTTP client
        def create_http_client
          Faraday.new do |conn|
            conn.ssl.verify = Clavis.configuration.should_verify_ssl?
            conn.ssl.min_version = Clavis.configuration.minimum_tls_version if Clavis.configuration.minimum_tls_version

            # Add middleware
            conn.request :url_encoded
            conn.response :json, content_type: /\bjson$/
            conn.adapter Faraday.default_adapter
          end
        end

        # Checks if a URL is using HTTPS
        # @param url [String] The URL to check
        # @return [Boolean] Whether the URL is using HTTPS
        def https?(url)
          return false if url.nil? || url.empty?

          begin
            uri = URI.parse(url)
            uri.scheme == "https"
          rescue URI::InvalidURIError
            false
          end
        end

        # Logs a warning if a URL is not using HTTPS
        # @param url [String] The URL to check
        # @param context [String] The context for the warning
        def warn_if_not_https(url, context = nil)
          return if https?(url)

          message = "WARNING: Non-HTTPS URL detected"
          message += " in #{context}" if context
          message += ": #{url}"

          Clavis.logger.warn(message)
        end

        private

        # Checks if a host is localhost
        # @param host [String] The host to check
        # @return [Boolean] Whether the host is localhost
        def localhost?(host)
          ["localhost", "127.0.0.1"].include?(host)
        end
      end
    end
  end
end
