# frozen_string_literal: true

module Clavis
  module Security
    module ParameterFilter
      SENSITIVE_PARAMETERS = [
        :code,           # Authorization code
        :token,          # Access token
        :access_token,   # Access token
        :refresh_token,  # Refresh token
        :id_token,       # ID token
        :client_secret,  # Client secret
        :state,          # CSRF state token
        :nonce,          # OIDC nonce
        :password,       # Just in case
        :secret          # Generic secret
      ].freeze

      class << self
        # Filters sensitive parameters from a hash
        # @param params [Hash] The parameters to filter
        # @return [Hash] The filtered parameters
        def filter_parameters(params)
          return params unless Clavis.configuration.parameter_filter_enabled
          return params if params.nil? || !params.is_a?(Hash)

          filtered_params = params.dup
          SENSITIVE_PARAMETERS.each do |param|
            filtered_params[param] = "[FILTERED]" if filtered_params.key?(param)

            # Also check for string keys
            string_param = param.to_s
            filtered_params[string_param] = "[FILTERED]" if filtered_params.key?(string_param)
          end

          filtered_params
        end

        # Installs the parameter filter in Rails if available
        # This should be called during initialization
        def install_rails_filter
          return unless defined?(Rails) && Rails.application&.config&.respond_to?(:filter_parameters)

          Rails.application.config.filter_parameters.concat(SENSITIVE_PARAMETERS)
          Clavis.logger.info("Installed Clavis parameter filters in Rails")
        end

        # Logs parameters safely by filtering sensitive values
        # @param params [Hash] The parameters to log
        # @param level [Symbol] The log level (:info, :debug, etc.)
        # @param message [String] The message to log
        def log_parameters(params, level: :debug, message: "Parameters")
          return unless Clavis.logger

          filtered = filter_parameters(params)
          Clavis.logger.send(level, "#{message}: #{filtered.inspect}")
        end
      end
    end
  end
end
