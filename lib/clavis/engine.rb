# frozen_string_literal: true

require "rails"

module Clavis
  class Engine < ::Rails::Engine
    isolate_namespace Clavis

    # Allow the routes to be namespaced with a unique identifier for each mount point
    # This prevents route name collisions when the engine is mounted multiple times
    mattr_accessor :route_namespace_id
    self.route_namespace_id = "clavis"

    # Class-level configuration option to control helper inclusion
    mattr_accessor :include_view_helpers
    self.include_view_helpers = true # Default to true

    # Class-level accessor for the route setup function
    mattr_accessor :setup_routes

    # Configuration flag to control automatic route installation
    mattr_accessor :auto_install_routes
    self.auto_install_routes = true # Default to true

    initializer "clavis.assets" do |app|
      # Add Clavis assets to the asset pipeline
      app.config.assets.paths << root.join("app", "assets", "stylesheets") if app.config.respond_to?(:assets)
      app.config.assets.paths << root.join("app", "assets", "javascripts") if app.config.respond_to?(:assets)
    end

    # Add an initializer to set up application routes when the engine is mounted
    initializer "clavis.routes", after: :add_routing_paths do |app|
      # Only install routes automatically if enabled
      if auto_install_routes && setup_routes.respond_to?(:call)
        # Call the setup_routes lambda to add routes to the parent application
        setup_routes.call(app)
        Clavis::Logging.log_info("Installed Clavis routes: auth_path and auth_callback_path helpers are now available")
      end
    end

    initializer "clavis.helpers" do
      ActiveSupport.on_load(:action_controller) do
        include Clavis::Controllers::Concerns::Authentication
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
    end

    config.to_prepare do
      # Make the view helpers available to the application
      ApplicationController.helper(Clavis::ViewHelpers) if defined?(ApplicationController)
    end
  end
end
