# frozen_string_literal: true

module MyApp
  module Providers
    # Example of a custom OAuth provider implementation
    # This example is for a fictional OAuth provider called "ExampleOAuth"
    class ExampleOAuth < Clavis::Providers::Base
      # Override the provider_name method if you want a different name than the class name
      def provider_name
        :example_oauth
      end

      # Required: Implement the authorization endpoint
      def authorization_endpoint
        "https://auth.example.com/oauth2/authorize"
      end

      # Required: Implement the token endpoint
      def token_endpoint
        "https://auth.example.com/oauth2/token"
      end

      # Required: Implement the userinfo endpoint
      def userinfo_endpoint
        "https://api.example.com/userinfo"
      end

      # Optional: Override the default scopes
      def default_scopes
        "profile email"
      end

      # Optional: Specify if this is an OpenID Connect provider
      def openid_provider?
        false
      end

      # Optional: Override the process_userinfo_response method to customize user info parsing
      protected

      def process_userinfo_response(response)
        data = JSON.parse(response.body, symbolize_names: true)

        # Map the provider's user info fields to a standardized format
        {
          id: data[:user_id],
          name: data[:display_name],
          email: data[:email_address],
          picture: data[:avatar_url]
        }
      end
    end
  end
end

# Register the custom provider with Clavis
Clavis.register_provider(:example_oauth, MyApp::Providers::ExampleOAuth)
