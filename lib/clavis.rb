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
require_relative "clavis/security/rate_limiter"
require "clavis/user_info_normalizer"

# Load required gems
require "jwt"
require "json"
require "faraday"

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
require_relative "clavis/controllers/concerns/session_management"
require_relative "clavis/view_helpers"

# Required for delegate method
require "active_support/core_ext/module/delegation"

# Create an alias for backward compatibility
module Clavis
  module Models
    # Alias for Clavis::Models::Concerns::OauthAuthenticatable
    # This makes it easier to include in user models as documented
    OauthAuthenticatable = Concerns::OauthAuthenticatable
  end
end

# Only load the engine if Rails is defined
begin
  require_relative "clavis/engine" if defined?(Rails)
rescue LoadError => e
  # Log a warning if we're unable to load the engine
  warn "Warning: Unable to load Clavis::Engine - #{e.message}" if defined?(Rails)
end

module Clavis
  class << self
    attr_writer :configuration

    def configure
      yield(configuration) if block_given?
      configuration.post_initialize
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

    # Define logger methods manually instead of using delegate
    def logger
      Logging.logger
    end

    def logger=(value)
      Logging.logger = value
    end

    def self.setup
      yield(configuration) if block_given?
      configuration.post_initialize
      self
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
