# frozen_string_literal: true

module Clavis
  class Configuration
    attr_accessor :providers, :default_callback_path, :default_scopes, :verbose_logging, :claims_processor,
                  :encrypt_tokens, :encryption_key, :use_rails_credentials, :parameter_filter_enabled,
                  :allowed_redirect_hosts, :exact_redirect_uri_matching, :allow_localhost_in_development,
                  :raise_on_invalid_redirect, :enforce_https, :allow_http_localhost, :verify_ssl,
                  :minimum_tls_version

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
    end

    def provider_configured?(provider_name)
      return false unless providers&.key?(provider_name.to_sym)

      provider_config = providers[provider_name.to_sym]
      client_id = provider_config[:client_id]
      client_secret = provider_config[:client_secret]

      !client_id.nil? && !client_id.empty? && !client_secret.nil? && !client_secret.empty?
    end

    def validate_provider!(provider_name)
      return if provider_configured?(provider_name)

      raise Clavis::ProviderNotConfigured.new(provider_name)
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
