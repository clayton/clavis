# frozen_string_literal: true

module Clavis
  class Configuration
    SUPPORTED_PROVIDERS = %i[google github facebook apple microsoft].freeze

    attr_accessor :providers, :default_callback_path, :default_scopes, :verbose_logging, :claims_processor,
                  :encrypt_tokens, :encryption_key, :use_rails_credentials, :parameter_filter_enabled,
                  :allowed_redirect_hosts, :exact_redirect_uri_matching, :allow_localhost_in_development,
                  :raise_on_invalid_redirect, :enforce_https, :allow_http_localhost, :verify_ssl,
                  :minimum_tls_version, :validate_inputs, :sanitize_inputs, :rotate_session_after_login,
                  :session_key_prefix, :logger, :log_level, :token_encryption_key, :csrf_protection_enabled,
                  :valid_redirect_schemes, :view_helpers_auto_include, :user_class, :user_finder_method

    def initialize
      @providers = {}
      @default_callback_path = "/auth/:provider/callback"
      @default_scopes = nil
      @verbose_logging = false
      @claims_processor = nil

      # Security-related defaults
      @encrypt_tokens = false
      @encryption_key = nil
      @use_rails_credentials = defined?(Rails)
      @parameter_filter_enabled = true

      # Redirect URI validation defaults
      @allowed_redirect_hosts = []
      @exact_redirect_uri_matching = false
      @allow_localhost_in_development = true
      @raise_on_invalid_redirect = true

      # HTTPS enforcement defaults
      @enforce_https = true
      @allow_http_localhost = true
      @verify_ssl = true
      @minimum_tls_version = :TLS1_2

      # Input validation configuration
      @validate_inputs = true
      @sanitize_inputs = true

      # Session management configuration
      @rotate_session_after_login = true
      @session_key_prefix = "clavis"

      # Additional configuration options
      @logger = nil
      @log_level = :info
      @token_encryption_key = nil
      @csrf_protection_enabled = true
      @valid_redirect_schemes = %w[http https]
      @view_helpers_auto_include = true

      # User creation configuration
      @user_class = "User"
      @user_finder_method = :find_or_create_from_clavis
    end

    # Returns the list of supported providers
    # @return [Array<Symbol>] List of supported provider symbols
    def self.supported_providers
      SUPPORTED_PROVIDERS
    end

    # Returns the list of configured providers
    # @return [Array<Symbol>] List of configured provider symbols
    def configured_providers
      providers.keys
    end

    def post_initialize
      # Set up engine view helpers based on configuration
      Clavis::Engine.include_view_helpers = @view_helpers_auto_include if defined?(Clavis::Engine)
    end

    def provider_configured?(provider_name)
      Rails.logger.debug "CLAVIS DEBUG: provider_configured? check for provider: #{provider_name}"
      provider_sym = provider_name.to_sym
      Rails.logger.debug "CLAVIS DEBUG: Available providers: #{providers.keys.inspect}"

      # Check if the provider is defined in the configuration
      unless providers&.key?(provider_sym)
        Rails.logger.error "CLAVIS DEBUG: Provider '#{provider_name}' is not defined in the configuration"
        Clavis::Logging.log_error("Provider '#{provider_name}' is not defined in the configuration")
        return false
      end

      provider_config = providers[provider_sym]
      Rails.logger.debug "CLAVIS DEBUG: Provider config: #{provider_config.inspect}"

      # Check for required credentials
      if provider_config[:client_id].nil? || provider_config[:client_id].empty?
        Rails.logger.error "CLAVIS DEBUG: Provider '#{provider_name}' is missing client_id"
        Clavis::Logging.log_error("Provider '#{provider_name}' is missing client_id")
        return false
      end

      if provider_config[:client_secret].nil? || provider_config[:client_secret].empty?
        Rails.logger.error "CLAVIS DEBUG: Provider '#{provider_name}' is missing client_secret"
        Clavis::Logging.log_error("Provider '#{provider_name}' is missing client_secret")
        return false
      end

      # Check for redirect_uri if required by provider
      if %i[google github facebook microsoft].include?(provider_sym) &&
         (provider_config[:redirect_uri].nil? || provider_config[:redirect_uri].empty?)
        Rails.logger.error "CLAVIS DEBUG: Provider '#{provider_name}' is missing redirect_uri"
        Clavis::Logging.log_error("Provider '#{provider_name}' is missing redirect_uri")
        return false
      end

      # All checks passed
      Rails.logger.debug "CLAVIS DEBUG: Provider '#{provider_name}' is properly configured"
      true
    end

    def validate_provider!(provider_name)
      Rails.logger.debug "CLAVIS DEBUG: validate_provider! called for #{provider_name}"
      result = provider_configured?(provider_name)
      Rails.logger.debug "CLAVIS DEBUG: provider_configured? returned #{result.inspect}"

      unless result
        Rails.logger.error "CLAVIS DEBUG: Provider '#{provider_name}' is not configured properly"
        raise Clavis::ProviderNotConfigured, provider_name
      end

      Rails.logger.debug "CLAVIS DEBUG: Provider '#{provider_name}' validation successful"
    end

    def provider_config(provider_name)
      validate_provider!(provider_name)

      # If Rails credentials are enabled, merge with provider config
      if use_rails_credentials && defined?(Rails) && Rails.application.respond_to?(:credentials)
        credentials_config = Rails.application.credentials.dig(:clavis, :providers, provider_name.to_sym)
        if credentials_config && !credentials_config.to_h.empty?
          return providers[provider_name.to_sym].merge(credentials_config.to_h)
        end
      end

      providers[provider_name.to_sym]
    end

    def callback_path(provider_name)
      path = provider_config(provider_name)[:redirect_uri] || default_callback_path
      path.gsub(":provider", provider_name.to_s)
    end

    def effective_encryption_key
      return nil unless encrypt_tokens

      if use_rails_credentials && defined?(Rails) && Rails.application.respond_to?(:credentials)
        rails_key = Rails.application.credentials.dig(:clavis, :encryption_key)
        return rails_key if rails_key && !rails_key.to_s.empty?
      end

      encryption_key
    end

    def should_verify_ssl?
      # Always verify SSL in production
      return true if defined?(Rails) && Rails.env.production?

      # Otherwise, use the configured value
      verify_ssl
    end
  end
end
