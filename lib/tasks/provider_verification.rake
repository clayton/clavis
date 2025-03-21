# frozen_string_literal: true

namespace :clavis do
  desc "Verify all providers implement required methods"
  task verify_providers: :environment do
    require "clavis"

    # Define the methods all providers must implement
    required_methods = %i[
      process_callback
      authorize_url
      token_exchange
      get_user_info
      refresh_token
      provider_name
      authorization_endpoint
      token_endpoint
      userinfo_endpoint
      default_scopes
      openid_provider?
    ]

    # Get all provider classes
    providers = [
      Clavis::Providers::Google,
      Clavis::Providers::Github,
      Clavis::Providers::Microsoft,
      Clavis::Providers::Facebook,
      Clavis::Providers::Apple,
      Clavis::Providers::Generic
    ]

    # Initialize a provider with fake credentials
    args = {
      client_id: "fake-client-id",
      client_secret: "fake-client-secret",
      redirect_uri: "http://localhost:3000/callback"
    }

    missing_methods = []
    errors = []

    # Check each provider
    providers.each do |provider_class|
      Rails.logger.debug { "Checking #{provider_class.name}..." }

      begin
        provider = provider_class.new(args)

        required_methods.each do |method|
          missing_methods << "#{provider_class.name} is missing method: #{method}" unless provider.respond_to?(method)
        end
      rescue StandardError => e
        errors << "Error initializing #{provider_class.name}: #{e.message}"
      end
    end

    # Report results
    if missing_methods.any? || errors.any?
      Rails.logger.debug "FAILURES:"

      if missing_methods.any?
        Rails.logger.debug "\nMissing Methods:"
        Rails.logger.debug missing_methods.join("\n")
      end

      if errors.any?
        Rails.logger.debug "\nInitialization Errors:"
        Rails.logger.debug errors.join("\n")
      end

      exit 1
    else
      Rails.logger.debug "✅ All providers implement required methods."
    end
  end
end
