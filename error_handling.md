# Clavis Error Handling Strategy

## Overview

Clavis implements a structured error handling system that provides:

1. Clear, descriptive error messages
2. Specific error types for different failures
3. Rails logger integration
4. Easy error rescue patterns for application code

## Error Hierarchy

```
Clavis::Error (base class)
├── ConfigurationError
│   ├── ProviderNotConfigured
│   └── MissingConfiguration
├── AuthenticationError
│   ├── InvalidState
│   ├── MissingState
│   └── AuthorizationDenied
├── TokenError
│   ├── InvalidToken
│   ├── ExpiredToken
│   ├── InvalidGrant
│   └── InvalidAccessToken
└── ProviderError
    ├── UnsupportedProvider
    └── ProviderAPIError
```

## Error Classes

### Configuration Errors

- **ConfigurationError**: Base class for configuration-related errors
- **ProviderNotConfigured**: Raised when trying to use an unconfigured provider
- **MissingConfiguration**: Raised when required configuration values are missing

### Authentication Errors

- **AuthenticationError**: Base class for authentication flow errors
- **InvalidState**: Raised when state parameter validation fails (CSRF protection)
- **MissingState**: Raised when state parameter is missing from the session
- **AuthorizationDenied**: Raised when the user denies authorization at the provider

### Token Errors

- **TokenError**: Base class for token-related errors
- **InvalidToken**: Raised when token validation fails
- **ExpiredToken**: Raised when a token has expired
- **InvalidGrant**: Raised when an authorization code is invalid or expired
- **InvalidAccessToken**: Raised when using an invalid access token

### Provider Errors

- **ProviderError**: Base class for provider-related errors
- **UnsupportedProvider**: Raised when trying to use an unsupported provider
- **ProviderAPIError**: Raised when a provider API returns an error

## Implementation

```ruby
# lib/clavis/errors.rb
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
      
      class_name = self.class.name.split('::').last
      words = class_name.gsub(/([A-Z])/, ' \1').strip.split(' ')
      words.join(' ').downcase
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
```

## Logging Integration

All errors are automatically logged with appropriate log levels:

```ruby
# lib/clavis/logging.rb
module Clavis
  module Logging
    def self.log_error(error)
      case error
      when Clavis::AuthorizationDenied
        # User chose to cancel, not a real error
        Rails.logger.info("[Clavis] Authorization denied: #{error.message}")
      when Clavis::InvalidState, Clavis::MissingState
        # Could be session expiration or CSRF attempt
        Rails.logger.warn("[Clavis] Security issue: #{error.class.name} - #{error.message}")
      when Clavis::ProviderAPIError
        # Provider API errors
        Rails.logger.error("[Clavis] Provider API error: #{error.message}")
      when Clavis::ConfigurationError
        # Configuration issues
        Rails.logger.error("[Clavis] Configuration error: #{error.message}")
      else
        # All other errors
        Rails.logger.error("[Clavis] #{error.class.name}: #{error.message}")
      end
      
      # Only log backtraces for unexpected errors in debug mode
      unless error.is_a?(Clavis::AuthorizationDenied)
        Rails.logger.debug("[Clavis] #{error.backtrace.join("\n")}")
      end
    end
  end
end
```

## Error Handling in Controllers

Example of how to handle Clavis errors in a controller:

```ruby
# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController
  include Clavis::Controllers::Concerns::Authentication
  
  def create_from_oauth
    oauth_callback do |user, auth_hash|
      session[:user_id] = user.id
      redirect_to root_path, notice: "Signed in successfully!"
    end
  rescue Clavis::AuthorizationDenied
    # User cancelled the authentication
    redirect_to login_path, notice: "Authentication cancelled"
  rescue Clavis::InvalidState, Clavis::MissingState
    # Session expired or possible CSRF attempt
    redirect_to login_path, alert: "Authentication session expired. Please try again."
  rescue Clavis::TokenError => e
    # Token-related errors
    Clavis::Logging.log_error(e)
    redirect_to login_path, alert: "Authentication failed. Please try again."
  rescue Clavis::ProviderAPIError => e
    # Provider API errors
    Clavis::Logging.log_error(e)
    redirect_to login_path, alert: "Service temporarily unavailable. Please try again later."
  rescue Clavis::Error => e
    # Catch all other Clavis errors
    Clavis::Logging.log_error(e)
    redirect_to login_path, alert: "Authentication failed: #{e.message}"
  end
end
```

## Custom Error Pages

For a better user experience, consider creating custom error pages:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  # Authentication failure routes
  get '/auth/failure', to: 'sessions#failure'
  
  # Other routes...
end

# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController
  def failure
    reason = params[:message] || "unknown reason"
    redirect_to login_path, alert: "Authentication failed: #{reason}"
  end
end
```

## Handling OAuth Error Responses

The OAuth 2.0 specification defines standard error responses. Clavis maps these to specific exceptions:

| OAuth Error | Clavis Exception |
|-------------|------------------|
| `invalid_request` | `Clavis::AuthenticationError` |
| `unauthorized_client` | `Clavis::AuthenticationError` |
| `access_denied` | `Clavis::AuthorizationDenied` |
| `unsupported_response_type` | `Clavis::ConfigurationError` |
| `invalid_scope` | `Clavis::ConfigurationError` |
| `server_error` | `Clavis::ProviderAPIError` |
| `temporarily_unavailable` | `Clavis::ProviderAPIError` |
| `invalid_client` | `Clavis::ConfigurationError` |
| `invalid_grant` | `Clavis::InvalidGrant` |
| `invalid_token` | `Clavis::InvalidToken` |

## Exception Middleware

For Rails API applications, consider adding a middleware to handle Clavis exceptions:

```ruby
# lib/clavis/middleware/exception_handler.rb
module Clavis
  module Middleware
    class ExceptionHandler
      def initialize(app)
        @app = app
      end
      
      def call(env)
        @app.call(env)
      rescue Clavis::Error => e
        Clavis::Logging.log_error(e)
        
        # Convert to appropriate HTTP response
        case e
        when Clavis::AuthorizationDenied
          # User cancelled
          [302, { 'Location' => '/auth/failure?message=denied' }, []]
        when Clavis::InvalidState, Clavis::MissingState
          # Security issues
          [302, { 'Location' => '/auth/failure?message=session_expired' }, []]
        when Clavis::TokenError
          # Token issues
          [302, { 'Location' => '/auth/failure?message=token_error' }, []]
        when Clavis::ProviderAPIError
          # Provider API issues
          [302, { 'Location' => '/auth/failure?message=provider_error' }, []]
        else
          # Other Clavis errors
          [302, { 'Location' => "/auth/failure?message=#{CGI.escape(e.message)}" }, []]
        end
      end
    end
  end
end
```

## Testing Error Handling

```ruby
# spec/error_handling_spec.rb
RSpec.describe "Error Handling" do
  describe "AuthorizationDenied error" do
    it "redirects to login path with appropriate message" do
      # Simulate user denying authorization
      get "/auth/google/callback", params: { error: "access_denied" }
      
      expect(response).to redirect_to(login_path)
      expect(flash[:notice]).to include("Authentication cancelled")
    end
  end
  
  describe "InvalidState error" do
    it "redirects to login path with session expired message" do
      # Simulate CSRF attack with invalid state
      get "/auth/google/callback", params: { code: "123", state: "invalid" }
      
      expect(response).to redirect_to(login_path)
      expect(flash[:alert]).to include("session expired")
    end
  end
  
  # More error handling tests...
end
``` 