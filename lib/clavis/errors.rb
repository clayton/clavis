# frozen_string_literal: true

module Clavis
  # Base error class for all Clavis errors
  class Error < StandardError; end

  # Configuration errors
  class ConfigurationError < Error; end

  class MissingConfiguration < ConfigurationError
    def initialize(missing_config)
      super("Missing configuration: #{missing_config}")
    end
  end

  class InvalidConfiguration < ConfigurationError
    def initialize(config_name, message)
      super("Invalid configuration for #{config_name}: #{message}")
    end
  end

  # Provider errors
  class ProviderError < Error; end

  class UnsupportedProvider < ProviderError
    def initialize(provider)
      super("Unsupported provider: #{provider}")
    end
  end

  class ProviderAPIError < ProviderError
    def initialize(provider, message)
      super("API error from #{provider}: #{message}")
    end
  end

  class ProviderNotConfigured < ProviderError
    def initialize(provider_or_message)
      if provider_or_message.is_a?(String) && provider_or_message.include?("not configured")
        # Already a detailed message
        super
      else
        # Just a provider name, create a detailed message
        provider = provider_or_message.to_s
        message = "Provider '#{provider}' is not properly configured. " \
                  "Please check your configuration in config/initializers/clavis.rb.\n" \
                  "Required fields for #{provider} provider: client_id, client_secret, and redirect_uri.\n" \
                  "Example configuration:\n" \
                  "Clavis.configure do |config|\n  " \
                  "config.providers = {\n    " \
                  "#{provider}: {\n      " \
                  "client_id: 'your_client_id',\n      " \
                  "client_secret: 'your_client_secret',\n      " \
                  "redirect_uri: 'https://your-app.com/auth/#{provider}/callback'\n    " \
                  "}\n  " \
                  "}\n" \
                  "end"
        super(message)
      end
    end
  end

  class InvalidHostedDomain < ProviderError
    def initialize(message = "User is not a member of the allowed hosted domain")
      super
    end
  end

  # OAuth errors
  class OAuthError < Error
    def initialize(message = "OAuth error")
      super
    end
  end

  # Authorization errors
  class AuthorizationError < Error; end

  class AuthorizationDenied < AuthorizationError
    def initialize(provider = nil)
      message = provider ? "User denied authorization for #{provider}" : "User denied authorization"
      super(message)
    end
  end

  class InvalidState < AuthorizationError
    def initialize
      super("Invalid state parameter in callback")
    end
  end

  class MissingState < AuthorizationError
    def initialize
      super("Missing state parameter in callback")
    end
  end

  class ExpiredState < AuthorizationError
    def initialize
      super("State token has expired")
    end
  end

  class InvalidNonce < AuthorizationError
    def initialize
      super("Invalid nonce in ID token")
    end
  end

  class MissingNonce < AuthorizationError
    def initialize
      super("Missing nonce in ID token or session")
    end
  end

  class InvalidRedirectUri < AuthorizationError
    def initialize(uri)
      super("Invalid redirect URI: #{uri}")
    end
  end

  # Authentication errors
  class AuthenticationError < Error
    def initialize(message = "Authentication failed")
      super
    end
  end

  # Token errors
  class TokenError < Error; end

  class InvalidToken < TokenError
    def initialize(message = "Invalid token")
      super
    end
  end

  class InvalidAccessToken < TokenError
    def initialize
      super("Invalid access token")
    end
  end

  class InvalidGrant < TokenError
    def initialize(message = "Invalid grant")
      super
    end
  end

  class ExpiredToken < TokenError
    def initialize
      super("Token has expired")
    end
  end

  # Client errors
  class InvalidClient < TokenError
    def initialize(message = "Invalid client credentials")
      super
    end
  end

  class UnauthorizedClient < TokenError
    def initialize(message = "The client is not authorized to use this grant type")
      super
    end
  end

  class UnsupportedGrantType < TokenError
    def initialize(message = "The grant type is not supported by the authorization server")
      super
    end
  end

  class InvalidScope < TokenError
    def initialize(message = "The requested scope is invalid or unknown")
      super
    end
  end

  class InsufficientScope < TokenError
    def initialize(message = "The token does not have the required scopes")
      super
    end
  end

  # Operation errors
  class UnsupportedOperation < Error
    def initialize(message)
      super("Unsupported operation: #{message}")
    end
  end

  # User errors
  class UserError < Error; end

  class UserCreationFailed < UserError
    def initialize(message = "Failed to create user")
      super
    end
  end

  class UserNotFound < UserError
    def initialize
      super("User not found")
    end
  end

  # View errors
  class ViewError < Error; end

  class InvalidButton < ViewError
    def initialize(provider)
      super("Invalid button provider: #{provider}")
    end
  end

  # Response-related errors
  class InvalidResponse < Error
    def initialize(message)
      super("Invalid response: #{message}")
    end
  end
end
