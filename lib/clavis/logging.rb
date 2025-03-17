# frozen_string_literal: true

require "logger"

module Clavis
  module Logging
    class << self
      def logger
        @logger ||= defined?(Rails) ? Rails.logger : Logger.new($stdout)
      end

      attr_writer :logger

      def log_level
        @log_level ||= :info
      end

      def log_level=(level)
        @log_level = level.to_sym
      end

      def log(message, level = :info)
        return unless logger
        return unless log_levels.index(level.to_sym) <= log_levels.index(log_level)

        logger.send(level, "[Clavis] #{message}")
      end

      def log_authorization_request(provider, params)
        sanitized_params = params.dup
        sanitized_params[:client_secret] = "[FILTERED]" if sanitized_params[:client_secret]

        log("Authorization request to #{provider}: #{sanitized_params.inspect}", :debug)
      end

      def log_authorization_callback(provider, success)
        if success
          log("Successfully processed authorization callback from #{provider}", :info)
        else
          log("Failed to process authorization callback from #{provider}", :error)
        end
      end

      def log_token_exchange(provider, success)
        if success
          log("Successfully exchanged token with #{provider}", :info)
        else
          log("Failed to exchange token with #{provider}", :error)
        end
      end

      def log_token_refresh(provider, success)
        if success
          log("Successfully refreshed token with #{provider}", :info)
        else
          log("Failed to refresh token with #{provider}", :error)
        end
      end

      def log_userinfo_request(provider, success)
        if success
          log("Successfully retrieved user info from #{provider}", :info)
        else
          log("Failed to retrieve user info from #{provider}", :error)
        end
      end

      def log_error(error)
        log("Error: #{error.message}", :error)
        log("Backtrace: #{error.backtrace.join("\n")}", :debug) if error.backtrace
      end

      private

      def log_levels
        %i[debug info warn error fatal]
      end
    end
  end
end
