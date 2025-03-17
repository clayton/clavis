# frozen_string_literal: true

module Clavis
  # Base error class
  class Error < StandardError
    def initialize(message = nil)
      @message = message
      super(format_message)
    end

    private

    def format_message
      return @message if @message

      class_name = self.class.name.split("::").last
      words = class_name.gsub(/([A-Z])/, ' \1').strip.split(" ")
      words.join(" ").downcase
    end
  end

  # Configuration errors
  class ConfigurationError < Error; end

  class ProviderNotConfigured < ConfigurationError
    def initialize(provider)
      @provider = provider
      super("Provider '#{provider}' is not configured")
    end
  end

  class MissingConfiguration < ConfigurationError
    def initialize(option)
      @option = option
      super("Missing required configuration option: #{option}")
    end
  end

  # Authentication errors
  class AuthenticationError < Error; end

  class InvalidState < AuthenticationError
    def initialize
      super("Invalid state parameter. This may be a CSRF attempt or the session expired")
    end
  end

  class MissingState < AuthenticationError
    def initialize
      super("Missing state parameter in session. Session may have expired")
    end
  end

  class AuthorizationDenied < AuthenticationError
    def initialize(reason = nil)
      @reason = reason
      super(reason ? "Authorization denied: #{reason}" : "Authorization denied by user")
    end
  end

  # Token errors
  class TokenError < Error; end

  class InvalidToken < TokenError
    def initialize(reason = nil)
      @reason = reason
      super(reason ? "Invalid token: #{reason}" : "Token validation failed")
    end
  end

  class ExpiredToken < TokenError
    def initialize
      super("Token has expired")
    end
  end

  class InvalidGrant < TokenError
    def initialize(reason = nil)
      @reason = reason
      super(reason ? "Invalid grant: #{reason}" : "Authorization code is invalid or expired")
    end
  end

  class InvalidAccessToken < TokenError
    def initialize
      super("Access token is invalid or expired")
    end
  end

  # Provider errors
  class ProviderError < Error; end

  class UnsupportedProvider < ProviderError
    def initialize(provider)
      @provider = provider
      super("Provider '#{provider}' is not supported")
    end
  end

  class ProviderAPIError < ProviderError
    def initialize(provider, error = nil)
      @provider = provider
      @error = error
      message = "Error from #{provider} API"
      message += ": #{error}" if error
      super(message)
    end
  end
end
