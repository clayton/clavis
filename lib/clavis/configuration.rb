# frozen_string_literal: true

module Clavis
  class Configuration
    attr_accessor :providers, :default_callback_path, :default_scopes, :verbose_logging, :claims_processor

    def initialize
      @providers = {}
      @default_callback_path = "/auth/:provider/callback"
      @default_scopes = nil
      @verbose_logging = false
      @claims_processor = nil
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
      providers[provider_name.to_sym]
    end

    def callback_path(provider_name)
      path = provider_config(provider_name)[:redirect_uri] || default_callback_path
      path.gsub(":provider", provider_name.to_s)
    end
  end
end
