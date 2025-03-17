# frozen_string_literal: true

require_relative "clavis/version"
require_relative "clavis/configuration"
require_relative "clavis/errors"
require_relative "clavis/logging"
require_relative "clavis/utils/state_store"
require_relative "clavis/utils/nonce_store"
require_relative "clavis/security/token_storage"
require_relative "clavis/security/parameter_filter"
require_relative "clavis/security/csrf_protection"
require_relative "clavis/security/redirect_uri_validator"
require_relative "clavis/security/https_enforcer"
require_relative "clavis/security/input_validator"
require_relative "clavis/security/session_manager"

# Only load provider classes if they're not already defined (for testing)
unless defined?(Clavis::Providers::Base)
  require_relative "clavis/providers/base"
  require_relative "clavis/providers/google"
  require_relative "clavis/providers/github"
  require_relative "clavis/providers/facebook"
  require_relative "clavis/providers/apple"
  require_relative "clavis/providers/microsoft"
  require_relative "clavis/providers/generic"
end

require_relative "clavis/oauth_identity"
require_relative "clavis/models/concerns/oauth_authenticatable"
require_relative "clavis/controllers/concerns/authentication"
require_relative "clavis/view_helpers"

# Only load the engine if Rails is defined and we're not in a test environment
begin
  require_relative "clavis/engine" if defined?(Rails) && !defined?(RSpec)
rescue LoadError
  # Engine couldn't be loaded, but that's okay in test environment
end

module Clavis
  class << self
    attr_writer :configuration

    def configure
      yield(configuration)
    end

    def configuration
      @configuration ||= Configuration.new
    end

    def reset_configuration!
      @configuration = Configuration.new
    end

    def provider(name, options = {})
      name = name.to_sym
      provider_class = provider_registry[name] ||
                       case name
                       when :google
                         Providers::Google
                       when :github
                         Providers::Github
                       when :facebook
                         Providers::Facebook
                       when :apple
                         Providers::Apple
                       when :microsoft
                         Providers::Microsoft
                       when :generic
                         Providers::Generic
                       else
                         raise UnsupportedProvider, name
                       end

      # Merge options with configuration
      config = configuration.providers[name] || {}
      config = config.merge(options)

      provider_class.new(config)
    end

    def register_provider(name, provider_class)
      provider_registry[name.to_sym] = provider_class
    end

    def provider_registry
      @provider_registry ||= {}
    end

    def logger
      Logging.logger
    end

    def logger=(logger)
      Logging.logger = logger
    end
  end
end

# Register built-in providers
Clavis.register_provider(:google, Clavis::Providers::Google)
Clavis.register_provider(:github, Clavis::Providers::Github)
Clavis.register_provider(:facebook, Clavis::Providers::Facebook)
Clavis.register_provider(:apple, Clavis::Providers::Apple)
Clavis.register_provider(:microsoft, Clavis::Providers::Microsoft)
Clavis.register_provider(:generic, Clavis::Providers::Generic)
