# frozen_string_literal: true

require "logger"

module Clavis
  module Logging
    class << self
      def logger
        @logger ||= defined?(Rails) ? Rails.logger : Logger.new($stdout)
      end

      attr_writer :logger

      # Check if verbose logging is enabled
      def verbose_logging?
        return false unless defined?(Clavis.configuration)

        Clavis.configuration.verbose_logging == true
      end

      # Log debug messages
      # @param message [String] The message to log
      def debug(message)
        return unless logger
        return if !message || message.empty?

        # Sanitize any potentially sensitive data
        sanitized_message = filter_sensitive_data(message)
        logger.debug("[Clavis] #{sanitized_message}")
      end

      # Log informational messages
      # @param message [String] The message to log
      # @param level [Symbol] The log level (:info, :debug, etc.)
      def log_info(message)
        return unless logger
        return if !message || message.empty?

        # Sanitize any potentially sensitive data
        sanitized_message = filter_sensitive_data(message)
        logger.info("[Clavis] #{sanitized_message}")
      end

      # Log error messages
      # @param error [Exception, String] The error to log
      def log_error(error)
        return unless logger

        case error
        when Exception
          logger.error("[Clavis] #{error.class.name}: #{error.message}")
          logger.debug("[Clavis] #{error.backtrace.join("\n")}") if error.backtrace
        when String
          logger.error("[Clavis] Error: #{error}")
        end
      end

      # Log security warnings - always logged at WARN level
      # @param message [String] The message to log
      def security_warning(message)
        return unless logger
        return if !message || message.empty?

        # Sanitize any potentially sensitive data
        sanitized_message = filter_sensitive_data(message)
        logger.warn("[Clavis Security Warning] #{sanitized_message}")
      end

      # The following methods are provided as aliases or for backwards compatibility

      def log(message, level = :info)
        return unless logger
        return if !message || message.empty?

        # Sanitize any potentially sensitive data
        sanitized_message = filter_sensitive_data(message)
        logger.send(level, "[Clavis] #{sanitized_message}")
      end

      # Older method signatures maintained for compatibility
      def log_token_refresh(provider, success, message = nil)
        return unless verbose_logging?

        log("Token refresh for #{provider}: #{success ? "success" : "failed"}#{message ? " - #{message}" : ""}")
      end

      def log_token_exchange(provider, success, details = nil)
        return unless verbose_logging?

        log("Token exchange for #{provider}: #{success ? "success" : "failed"}#{details ? " - #{details}" : ""}")
      end

      def log_userinfo_request(provider, success, details = nil)
        return unless verbose_logging?

        log("Userinfo request for #{provider}: #{success ? "success" : "failed"}#{details ? " - #{details}" : ""}")
      end

      def log_authorization_request(provider, params)
        return unless verbose_logging?

        sanitized_params = filter_sensitive_data(params.to_s)
        log("Authorization request for #{provider}: #{sanitized_params}")
      end

      def log_authorization_callback(provider, success)
        return unless verbose_logging?

        log("Authorization callback for #{provider}: #{success ? "success" : "failed"}")
      end

      # Log token verification results
      def log_token_verification(provider, success, details = nil)
        return unless verbose_logging?

        log("Token verification for #{provider}: #{success ? "success" : "failed"}#{details ? " - #{details}" : ""}")
      end

      # Log hosted domain verification results
      def log_hosted_domain_verification(provider, success, details = nil)
        return unless verbose_logging?

        log("Hosted domain verification for #{provider}: #{success ? "success" : "failed"}" \
            "#{details ? " - #{details}" : ""}")
      end

      # Log custom operation results
      # @param operation [String] The name of the operation
      # @param success [Boolean] Whether the operation was successful
      # @param details [String, nil] Optional details about the operation
      def log_custom(operation, success, details = nil)
        return unless verbose_logging?

        log("#{operation}: #{success ? "success" : "failed"}#{details ? " - #{details}" : ""}")
      end

      private

      # Filter potentially sensitive data from log messages
      def filter_sensitive_data(message)
        return message unless message.is_a?(String)

        # List of patterns to filter out
        patterns = [
          /client_secret=([^&\s]+)/i,
          /access_token=([^&\s]+)/i,
          /refresh_token=([^&\s]+)/i,
          /id_token=([^&\s]+)/i,
          /code=([^&\s]+)/i,
          /password=([^&\s]+)/i,
          /secret=([^&\s]+)/i,
          /api_key=([^&\s]+)/i,
          /key=([^&\s]+)/i,
          /"token":\s*"([^"]+)"/i,
          /"refresh_token":\s*"([^"]+)"/i,
          /"id_token":\s*"([^"]+)"/i,
          /"code":\s*"([^"]+)"/i
        ]

        filtered_message = message.dup
        patterns.each do |pattern|
          filtered_message.gsub!(pattern, '\0=[FILTERED]')
        end

        filtered_message
      end
    end
  end
end
