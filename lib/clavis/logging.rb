# frozen_string_literal: true

require "logger"

module Clavis
  module Logging
    class << self
      def logger
        @logger ||= defined?(Rails) ? Rails.logger : Logger.new($stdout)
      end

      attr_writer :logger

      # Only provide a minimal logging interface
      # for critical security warnings
      def security_warning(message)
        return unless logger
        return if !message || message.empty?

        # Sanitize any potentially sensitive data
        sanitized_message = filter_sensitive_data(message)
        logger.warn("[Clavis Security Warning] #{sanitized_message}")
      end

      # The following methods are provided as no-ops for test compatibility
      # They don't actually log anything in production

      def log(_message, _level = :info)
        # No-op implementation for test compatibility
      end

      def log_error(_error)
        # No-op implementation for test compatibility
      end

      def log_token_refresh(_provider, _success, _message = nil)
        # No-op implementation for test compatibility
      end

      def log_token_exchange(_provider, _success, _details = nil)
        # No-op implementation for test compatibility
      end

      def log_userinfo_request(_provider, _success, _details = nil)
        # No-op implementation for test compatibility
      end

      def log_authorization_request(_provider, _params)
        # No-op implementation for test compatibility
      end

      def log_authorization_callback(_provider, _success)
        # No-op implementation for test compatibility
      end

      private

      # Filter potentially sensitive data from log messages
      def filter_sensitive_data(message)
        return message unless message.is_a?(String)

        # Filter out common sensitive patterns
        filtered = message.dup

        # Filter OAuth tokens
        filtered.gsub!(%r{token[=:]\s*["']?[a-zA-Z0-9._~+/\-=]{20,}["']?}, "token=[FILTERED]")

        # Filter auth codes
        filtered.gsub!(%r{code[=:]\s*["']?[a-zA-Z0-9._~+/\-=]{10,}["']?}, "code=[FILTERED]")

        # Filter JWT tokens
        filtered.gsub!(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/, "[JWT_FILTERED]")

        # Filter client secrets and keys
        filtered.gsub!(%r{secret[=:]\s*["']?[a-zA-Z0-9._~+/\-=]{10,}["']?}, "secret=[FILTERED]")
        filtered.gsub!(%r{key[=:]\s*["']?[a-zA-Z0-9._~+/\-=]{10,}["']?}, "key=[FILTERED]")

        filtered
      end
    end
  end
end
