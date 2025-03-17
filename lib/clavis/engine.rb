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

    initializer "clavis.parameter_filter" do |app|
      if Clavis.configuration.parameter_filter_enabled
        # Add sensitive parameters to the filter parameters
        app.config.filter_parameters += %i[
          code token access_token refresh_token id_token
          client_secret private_key encryption_key
        ]

        Clavis.logger.info "Clavis: Parameter filtering enabled"
      end
    end

    initializer "clavis.log_security_configuration" do
      # Log token encryption configuration
      if Clavis.configuration.encrypt_tokens
        Clavis.logger.info "Clavis: Token encryption enabled"

        if Clavis.configuration.use_rails_credentials
          Clavis.logger.info "Clavis: Using Rails credentials for encryption key"
        elsif Clavis.configuration.encryption_key.present?
          Clavis.logger.info "Clavis: Using environment variable for encryption key"
        else
          Clavis.logger.warn "Clavis: Token encryption enabled but no encryption key provided"
        end
      end

      # Log redirect URI validation configuration
      if Clavis.configuration.allowed_redirect_hosts.any?
        Clavis.logger.info "Clavis: Redirect URI validation enabled for hosts: #{Clavis.configuration.allowed_redirect_hosts.join(", ")}"

        if Clavis.configuration.exact_redirect_uri_matching
          Clavis.logger.info "Clavis: Using exact matching for redirect URIs"
        end

        if Clavis.configuration.allow_localhost_in_development && Rails.env.development?
          Clavis.logger.info "Clavis: Allowing localhost in development environment"
        end
      else
        Clavis.logger.warn "Clavis: No allowed redirect hosts configured, all redirect URIs will be rejected in production"
      end

      # Log HTTPS enforcement configuration
      if Clavis.configuration.enforce_https
        Clavis.logger.info "Clavis: HTTPS enforcement enabled"

        if Clavis.configuration.allow_http_localhost && Rails.env.development?
          Clavis.logger.info "Clavis: Allowing HTTP for localhost in development environment"
        end

        if Clavis.configuration.verify_ssl
          Clavis.logger.info "Clavis: SSL certificate verification enabled"
          Clavis.logger.info "Clavis: Minimum TLS version: #{Clavis.configuration.minimum_tls_version}"
        else
          Clavis.logger.warn "Clavis: SSL certificate verification disabled (not recommended for production)"
        end
      else
        Clavis.logger.warn "Clavis: HTTPS enforcement disabled (not recommended for production)"
      end

      # Log input validation configuration
      if Clavis.configuration.validate_inputs
        Clavis.logger.info "Clavis: Input validation enabled"
      else
        Clavis.logger.warn "Clavis: Input validation disabled (not recommended for production)"
      end

      if Clavis.configuration.sanitize_inputs
        Clavis.logger.info "Clavis: Input sanitization enabled"
      else
        Clavis.logger.warn "Clavis: Input sanitization disabled (not recommended for production)"
      end

      # Log session management configuration
      if Clavis.configuration.rotate_session_after_login
        Clavis.logger.info "Clavis: Session rotation after login enabled"
      else
        Clavis.logger.warn "Clavis: Session rotation after login disabled (not recommended for production)"
      end
    end

    config.to_prepare do
      # Make the view helpers available to the application
      ApplicationController.helper(Clavis::ViewHelpers) if defined?(ApplicationController)
    end
  end
end
