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

  # Token errors
  class TokenError < Error; end

  class InvalidToken < TokenError
    def initialize(message = "Invalid token")
      super(message)
    end
  end

  class InvalidAccessToken < TokenError
    def initialize
      super("Invalid access token")
    end
  end

  class InvalidGrant < TokenError
    def initialize(message = "Invalid grant")
      super(message)
    end
  end

  class ExpiredToken < TokenError
    def initialize
      super("Token has expired")
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
      super(message)
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
end
