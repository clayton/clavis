# frozen_string_literal: true

require "rails"

module Clavis
  class Engine < ::Rails::Engine
    isolate_namespace Clavis

    initializer "clavis.assets" do |app|
      # Add Clavis assets to the asset pipeline
      app.config.assets.paths << root.join("app", "assets", "stylesheets") if app.config.respond_to?(:assets)
      app.config.assets.paths << root.join("app", "assets", "javascripts") if app.config.respond_to?(:assets)
    end

    initializer "clavis.helpers" do
      ActiveSupport.on_load(:action_controller) do
        include Clavis::Controllers::Concerns::Authentication
      end

      ActiveSupport.on_load(:action_view) do
        include Clavis::ViewHelpers
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

      # Log security configuration
      Rails.logger.info("Clavis security features initialized")
      Rails.logger.info("Token encryption: #{Clavis.configuration.encrypt_tokens ? "enabled" : "disabled"}")
      Rails.logger.info("Parameter filtering: #{Clavis.configuration.parameter_filter_enabled ? "enabled" : "disabled"}")
      Rails.logger.info("HTTPS enforcement: #{Clavis.configuration.enforce_https ? "enabled" : "disabled"}")
      Rails.logger.info("SSL verification: #{Clavis.configuration.should_verify_ssl? ? "enabled" : "disabled"}")
      Rails.logger.info("Minimum TLS version: #{Clavis.configuration.minimum_tls_version}")

      if Clavis.configuration.allowed_redirect_hosts.any?
        Rails.logger.info("Allowed redirect hosts: #{Clavis.configuration.allowed_redirect_hosts.join(", ")}")
      else
        Rails.logger.warn("No allowed redirect hosts configured. All redirect URIs will be rejected.")
      end

      # Check for insecure redirect URIs
      Clavis.configuration.providers.each do |provider_name, config|
        if config[:redirect_uri] && !Clavis::Security::HttpsEnforcer.https?(config[:redirect_uri])
          if Rails.env.production?
            Rails.logger.warn("Non-HTTPS redirect URI detected for #{provider_name}: #{config[:redirect_uri]}")
            Rails.logger.warn("This will be automatically upgraded to HTTPS in production.")
          else
            Rails.logger.info("Non-HTTPS redirect URI detected for #{provider_name}: #{config[:redirect_uri]}")
            Rails.logger.info("This is allowed in development but will be upgraded to HTTPS in production.")
          end
        end
      end
    end

    config.to_prepare do
      # Make the view helpers available to the application
      ApplicationController.helper(Clavis::ViewHelpers) if defined?(ApplicationController)
    end
  end
end
