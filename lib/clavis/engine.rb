# frozen_string_literal: true

require "rails"
require_relative "controllers/concerns/authentication"
require_relative "controllers/concerns/session_management"
require_relative "security/rate_limiter"

module Clavis
  class Engine < ::Rails::Engine
    isolate_namespace Clavis

    # Allow the routes to be namespaced with a unique identifier for each mount point
    # This prevents route name collisions when the engine is mounted multiple times
    mattr_accessor :route_namespace_id
    self.route_namespace_id = "clavis"

    # Minimum TLS version for secure requests
    # At the application level, this is handled by Rails 7+ directly
    # At the engine level, we need to set it manually for Net::HTTP
    config.before_initialize do |_app|
      require "net/http"
      # Set minimum TLS version to 1.2 for security
      # Can be upgraded to TLS 1.3 when supported by all platforms
      begin
        # Use min_version instead of ssl_version for better compatibility
        if defined?(OpenSSL::SSL::TLS1_2_VERSION)
          OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:min_version] = OpenSSL::SSL::TLS1_2_VERSION
        end
      rescue StandardError => e
        # Log the error but don't crash
        Clavis.logger.warn("Could not set minimum TLS version: #{e.message}")
      end
    end

    # Expose Clavis view helpers to the host application
    class << self
      attr_accessor :include_view_helpers
    end

    # Default to true - can be changed in configuration
    self.include_view_helpers = true

    # Setup routes lambda - will be called if auto_install_routes is true
    # Takes a single argument (app) which is the Rails application
    # Define this before the initializer so it can be overridden if needed
    mattr_accessor :setup_routes, default: lambda { |app|
      # Mount the engine routes at /auth by default
      app.routes.draw do
        # Add mount point to the application routes
        mount Clavis::Engine => "/auth"
      end
    }

    # Whether to automatically install routes
    mattr_accessor :auto_install_routes, default: true

    # Setup Rack::Attack middleware for rate limiting
    initializer "clavis.rack_attack", before: :load_config_initializers do |app|
      # Install Rack::Attack if available
      Clavis::Security::RateLimiter.install(app)
    end

    initializer "clavis.assets" do |app|
      # Add Clavis assets to the asset pipeline
      app.config.assets.paths << root.join("app", "assets", "stylesheets") if app.config.respond_to?(:assets)
      app.config.assets.paths << root.join("app", "assets", "javascripts") if app.config.respond_to?(:assets)

      # Explicitly precompile clavis assets if precompile array is available
      if app.config.respond_to?(:assets) && app.config.assets.respond_to?(:precompile)
        app.config.assets.precompile += %w[clavis.css clavis.js]
      end

      # For Rails 7+ with propshaft or jsbundling
      if defined?(Propshaft) || defined?(Jsbundling)
        app.config.assets.precompile << "clavis.css" if app.config.respond_to?(:assets)
        app.config.importmap.pin "clavis", to: "clavis" if app.config.respond_to?(:importmap)
      end
    end

    initializer "clavis.routes", after: :add_routing_paths do |app|
      # Only install routes automatically if enabled
      if auto_install_routes && setup_routes.respond_to?(:call)
        # Call the setup_routes lambda to add routes to the parent application
        setup_routes.call(app)
      end
    end

    initializer "clavis.helpers" do
      ActiveSupport.on_load(:action_controller) do
        include Clavis::Controllers::Concerns::Authentication
        include Clavis::Controllers::Concerns::SessionManagement
      end

      # Include view helpers based on configuration (default: true)
      ActiveSupport.on_load(:action_view) do
        include Clavis::ViewHelpers
      end

      # Make ViewHelpers available to ApplicationHelper
      ActiveSupport.on_load(:after_initialize) do
        if defined?(ApplicationHelper) && ApplicationHelper.included_modules.exclude?(Clavis::ViewHelpers)
          ApplicationHelper.include(Clavis::ViewHelpers)
        end
      end
    end

    initializer "clavis.logger" do
      config.after_initialize do
        Clavis::Logging.logger = Rails.logger if defined?(Rails) && Rails.respond_to?(:logger)
      end
    end

    initializer "clavis.security" do |_app|
      # Install parameter filters
      Clavis::Security::ParameterFilter.install_rails_filter

      # Set default allowed redirect hosts from Rails application host
      if Clavis.configuration.allowed_redirect_hosts.empty? && Rails.application.config.respond_to?(:hosts)
        Clavis.configuration.allowed_redirect_hosts = Array(Rails.application.config.hosts)
      end

      # Only log critical security warnings
      if Clavis.configuration.allowed_redirect_hosts.empty?
        Clavis::Logging.security_warning("No allowed redirect hosts configured. All redirect URIs will be rejected.")
      end

      # Check for insecure redirect URIs in production
      if Rails.env.production?
        Clavis.configuration.providers.each do |provider_name, config|
          next unless config[:redirect_uri] && !Clavis::Security::HttpsEnforcer.https?(config[:redirect_uri])

          message = "Non-HTTPS redirect URI detected for #{provider_name}: "
          message += config[:redirect_uri].to_s
          Clavis::Logging.security_warning(message)
        end
      end
    end

    initializer "clavis.parameter_filter" do |app|
      if Clavis.configuration.parameter_filter_enabled
        # Add sensitive parameters to the filter parameters
        app.config.filter_parameters += %i[
          code token access_token refresh_token id_token
          client_secret private_key encryption_key
        ]
      end
    end

    initializer "clavis.security_warnings" do
      # Only log critical security warnings
      if !Clavis.configuration.encrypt_tokens && Rails.env.production?
        Clavis::Logging.security_warning("Token encryption disabled in production (not recommended)")
      end

      if Clavis.configuration.encrypt_tokens &&
         !Clavis.configuration.use_rails_credentials &&
         !Clavis.configuration.encryption_key.present?
        Clavis::Logging.security_warning("Token encryption enabled but no encryption key provided")
      end

      if !Clavis.configuration.enforce_https && Rails.env.production?
        Clavis::Logging.security_warning("HTTPS enforcement disabled in production (not recommended)")
      end

      if !Clavis.configuration.verify_ssl && Rails.env.production?
        Clavis::Logging.security_warning("SSL certificate verification disabled in production (not recommended)")
      end

      if !Clavis.configuration.validate_inputs && Rails.env.production?
        Clavis::Logging.security_warning("Input validation disabled in production (not recommended)")
      end

      if !Clavis.configuration.sanitize_inputs && Rails.env.production?
        Clavis::Logging.security_warning("Input sanitization disabled in production (not recommended)")
      end

      if !Clavis.configuration.rotate_session_after_login && Rails.env.production?
        Clavis::Logging.security_warning("Session rotation after login disabled in production (not recommended)")
      end

      if !Clavis.configuration.rate_limiting_enabled && Rails.env.production?
        Clavis::Logging.security_warning("Rate limiting disabled in production (not recommended)")
      end
    end

    config.to_prepare do
      # Make the view helpers available to the application
      ApplicationController.helper(Clavis::ViewHelpers) if defined?(ApplicationController)
    end
  end
end
