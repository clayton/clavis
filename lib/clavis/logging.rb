# frozen_string_literal: true

require "logger"

module Clavis
  module Logging
    def self.logger
      return Rails.logger if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
      return @logger if @logger

      @logger = Logger.new($stdout)
      @logger.level = Logger::INFO
      @logger
    end

    def self.log_error(error)
      case error
      when Clavis::AuthorizationDenied
        # User chose to cancel, not a real error
        logger.info("[Clavis] Authorization denied: #{error.message}")
      when Clavis::InvalidState, Clavis::MissingState
        # Could be session expiration or CSRF attempt
        logger.warn("[Clavis] Security issue: #{error.class.name} - #{error.message}")
      when Clavis::ProviderAPIError
        # Provider API errors
        logger.error("[Clavis] Provider API error: #{error.message}")
      when Clavis::ConfigurationError
        # Configuration issues
        logger.error("[Clavis] Configuration error: #{error.message}")
      else
        # All other errors
        logger.error("[Clavis] #{error.class.name}: #{error.message}")
      end

      # Only log backtraces for unexpected errors in debug mode
      return if error.is_a?(Clavis::AuthorizationDenied)

      logger.debug("[Clavis] #{error.backtrace.join("\n")}")
    end

    def self.log_authorization_request(provider, params)
      logger.info("[Clavis] Authorization request initiated for provider: #{provider}")
      logger.debug("[Clavis] Authorization parameters: #{params.except(:client_secret).inspect}")
    end

    def self.log_authorization_callback(provider, success)
      if success
        logger.info("[Clavis] Successful authorization callback from provider: #{provider}")
      else
        logger.warn("[Clavis] Failed authorization callback from provider: #{provider}")
      end
    end

    def self.log_token_exchange(provider, success)
      if success
        logger.info("[Clavis] Successful token exchange with provider: #{provider}")
      else
        logger.warn("[Clavis] Failed token exchange with provider: #{provider}")
      end
    end
  end
end
