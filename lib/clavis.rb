# frozen_string_literal: true

require_relative "clavis/version"
require_relative "clavis/errors"
require_relative "clavis/logging"
require_relative "clavis/configuration"
require_relative "clavis/utils/secure_token"
require_relative "clavis/providers/base"
require_relative "clavis/providers/google"
require_relative "clavis/controllers/concerns/authentication"
require_relative "clavis/models/concerns/oauth_authenticatable"
require_relative "clavis/view_helpers"

module Clavis
  class << self
    attr_writer :configuration

    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration)
    end

    def reset_configuration!
      @configuration = Configuration.new
    end

    def provider(provider_name)
      provider_name = provider_name.to_sym
      configuration.validate_provider!(provider_name)

      provider_class = provider_registry[provider_name] ||
                       raise(UnsupportedProvider.new(provider_name))

      provider_class.new(configuration.provider_config(provider_name))
    end

    def register_provider(name, provider_class)
      provider_registry[name.to_sym] = provider_class
    end

    def provider_registry
      @provider_registry ||= {}
    end
  end
end

# Register built-in providers
Clavis.register_provider(:google, Clavis::Providers::Google)
