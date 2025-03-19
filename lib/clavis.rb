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
require "clavis/user_info_normalizer"

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
      Rails.logger.debug "CLAVIS DEBUG: Clavis.configure called"
      yield(configuration) if block_given?
      configuration.post_initialize
      Rails.logger.debug "CLAVIS DEBUG: Clavis.configure completed, providers: #{configuration.providers.keys.inspect}"
    end

    def configuration
      @configuration ||= Configuration.new
    end

    def reset_configuration!
      @configuration = Configuration.new
    end

    def provider(name, options = {})
      Rails.logger.debug "CLAVIS DEBUG: Clavis.provider called with name: #{name.inspect}"

      begin
        name = name.to_sym
        Rails.logger.debug "CLAVIS DEBUG: Looking up provider class for #{name}"

        provider_class = provider_registry[name] ||
                         case name
                         when :google
                           Rails.logger.debug "CLAVIS DEBUG: Using Google provider class"
                           Providers::Google
                         when :github
                           Rails.logger.debug "CLAVIS DEBUG: Using GitHub provider class"
                           Providers::Github
                         when :facebook
                           Rails.logger.debug "CLAVIS DEBUG: Using Facebook provider class"
                           Providers::Facebook
                         when :apple
                           Rails.logger.debug "CLAVIS DEBUG: Using Apple provider class"
                           Providers::Apple
                         when :microsoft
                           Rails.logger.debug "CLAVIS DEBUG: Using Microsoft provider class"
                           Providers::Microsoft
                         when :generic
                           Rails.logger.debug "CLAVIS DEBUG: Using Generic provider class"
                           Providers::Generic
                         else
                           Rails.logger.error "CLAVIS DEBUG: Unsupported provider: #{name}"
                           raise UnsupportedProvider, name
                         end

        # Merge options with configuration
        Rails.logger.debug "CLAVIS DEBUG: Getting provider config from configuration"
        config = configuration.providers[name] || {}
        config = config.merge(options)
        Rails.logger.debug "CLAVIS DEBUG: Final provider config (sanitized): #{config.except(:client_secret).inspect}"

        Rails.logger.debug "CLAVIS DEBUG: Instantiating provider"
        instance = provider_class.new(config)
        Rails.logger.debug "CLAVIS DEBUG: Provider instance created: #{instance.class.name}"

        instance
      rescue StandardError => e
        Rails.logger.error "CLAVIS DEBUG: Error in Clavis.provider: #{e.class.name} - #{e.message}"
        Rails.logger.error "CLAVIS DEBUG: Backtrace: #{e.backtrace.join("\n")}"
        raise
      end
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

      # Debug provider setup
      begin
        Rails.logger.debug "CLAVIS DEBUG: ----------------------------------------------"
        Rails.logger.debug "CLAVIS DEBUG: Clavis setup complete, dumping configuration:"
        Rails.logger.debug "CLAVIS DEBUG: Providers configured: #{configuration.providers.keys.inspect}"

        # Check if provider classes are loaded
        Rails.logger.debug "CLAVIS DEBUG: Provider classes loaded:"
        [
          ["Clavis::Providers::Base", defined?(Clavis::Providers::Base)],
          ["Clavis::Providers::Google", defined?(Clavis::Providers::Google)],
          ["Clavis::Providers::Github", defined?(Clavis::Providers::Github)],
          ["Clavis::Providers::Facebook", defined?(Clavis::Providers::Facebook)],
          ["Clavis::Providers::Apple", defined?(Clavis::Providers::Apple)],
          ["Clavis::Providers::Microsoft", defined?(Clavis::Providers::Microsoft)]
        ].each do |provider_class, result|
          Rails.logger.debug "CLAVIS DEBUG: #{provider_class} loaded? #{result || "No"}"
        end

        Rails.logger.debug "CLAVIS DEBUG: ----------------------------------------------"
      rescue StandardError => e
        Rails.logger.error "CLAVIS DEBUG: Error in Clavis.setup debug: #{e.message}"
      end

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
