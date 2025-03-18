# Clavis: Large Language Model Documentation

This document provides detailed information about the Clavis gem for large language models to understand its architecture, functionality, and implementation details.

## Quick Start Guide for Implementation

Here's how to implement Clavis in a Rails application with minimal steps:

```ruby
# Step 1: Add to Gemfile
gem 'clavis'

# Step 2: Run migrations
# $ rails clavis:install:migrations
# $ rails db:migrate

# Step 3: Configure a provider (in config/initializers/clavis.rb)
Clavis.configure do |config|
  config.providers = {
    github: {
      client_id: ENV["GITHUB_CLIENT_ID"],
      client_secret: ENV["GITHUB_CLIENT_SECRET"]
    }
  }
end

# Step 4: Mount the engine in routes.rb
# This automatically sets up all required routes including
# auth_path and auth_callback_path helpers
mount Clavis::Engine => "/"

# Step 5: Include in User model
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
  
  # Helper method for conditional password validation
  def password_required?
    !oauth_user?
  end
end
```

The key components are:
1. Engine mounting (provides routes automatically)
2. Provider configuration
3. Model integration
4. Optional controller customization (not required for basic functionality)

## Table of Contents

1. [Overview](#overview)
   - [Key Assumptions](#key-assumptions)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Authentication Flow](#authentication-flow)
5. [Provider Implementation](#provider-implementation)
6. [Token Refresh](#token-refresh)
7. [Custom Providers](#custom-providers)
   - [Generic Provider](#generic-provider)
   - [Custom Provider Class](#custom-provider-class)
   - [Registering Custom Providers](#registering-custom-providers)
8. [Error Handling](#error-handling)
9. [Security Considerations](#security-considerations)
10. [Integration Points](#integration-points)
11. [Usage Examples](#usage-examples)
    - [Basic Setup](#basic-setup)
    - [Accessing Standardized User Info](#accessing-standardized-user-info)
    - [Controller Integration](#controller-integration)

## Overview

Clavis is a Ruby gem that implements the OAuth 2.0 and OpenID Connect (OIDC) protocols for Rails applications. It focuses on providing a simple "Sign in with ____" experience while maintaining security and adherence to relevant specifications.

### Key Assumptions

Clavis makes the following fundamental assumptions about its usage:

1. You're using Rails 7+ for your application
2. You've got a User model and some form of authentication already in place, ideally the Rails 8 authentication generator
3. You're trying to go fast and not spend time on configuration details

## Architecture

### Core Components

1. **Configuration System**
   - Central configuration object that stores provider settings, default options, and customization parameters
   - Configuration validation to ensure proper setup before use
   - Support for both environment variables and Rails credentials

2. **Provider Framework**
   - Abstract base class that implements common OAuth/OIDC flows
   - Provider-specific implementations that handle endpoint differences and requirements
   - Standardized interface for authorization, token exchange, and user info retrieval

3. **Authentication Flow**
   - Controller concern for handling OAuth/OIDC requests and callbacks
   - Secure state parameter management for CSRF protection
   - ID token validation according to OIDC specifications

4. **User Management**
   - Model concern for mapping OAuth/OIDC responses to user records
   - Configurable user creation and updating
   - Support for handling multiple providers per user

5. **View Components**
   - Button helpers with SVG icons for popular providers
   - Customizable styling and text
   - Validation to prevent display of unconfigured providers

6. **Rails Integration**
   - Rails engine for routes and assets
   - Generators for controllers, views, and migrations
   - Seamless integration with existing authentication systems

## Implementation Details

### Callback URI Format

The callback URI is a critical part of the OAuth flow, and it must be correctly configured both in the provider dashboard and in the Clavis configuration. The proper format is:

```ruby
https://your-domain.com/auth/:provider/callback
```

Where `:provider` is replaced with the name of the provider (e.g., google, github, etc.).

A common mistake is setting just the base domain (e.g., `http://localhost:3000`) as the callback URI in the provider's dashboard. This will cause authentication to fail because the provider will not redirect back to the correct endpoint.

Examples of correctly formatted callback URIs:
- For Google: `https://example.com/auth/google/callback`
- For GitHub: `https://example.com/auth/github/callback` 
- For development: `http://localhost:3000/auth/google/callback`

The callback URI must exactly match what is configured in the provider's dashboard, including the protocol (http/https), domain, port (if non-standard), and the full path.

### OAuth Flow Implementation

The core OAuth 2.0 Authorization Code Flow is implemented as follows:

1. **Authorization Request**
   ```ruby
   # Method in Clavis::Providers::Base
   def authorize_url(state:, nonce:, scope:)
     params = {
       response_type: "code",
       client_id: client_id,
       redirect_uri: redirect_uri,
       scope: scope || default_scopes,
       state: state
     }
     
     # Add nonce for OIDC
     params[:nonce] = nonce if openid_scope?(scope)
     
     "#{authorization_endpoint}?#{params.to_query}"
   end
   ```

2. **Authorization Callback**
   ```ruby
   # Method in Clavis::Controllers::Concerns::Authentication
   def oauth_callback
     # Verify state parameter to prevent CSRF
     validate_state!(params[:state])
     
     # Exchange code for tokens
     auth_hash = provider.process_callback(params[:code], session.delete(:oauth_state))
     
     # Find or create user
     user = find_or_create_user_from_oauth(auth_hash)
     
     # Yield to application code
     yield(user, auth_hash) if block_given?
   end
   ```

3. **Token Exchange**
   ```ruby
   # Method in Clavis::Providers::Base
   def token_exchange(code:, expected_state: nil)
     response = http_client.post(token_endpoint, {
       grant_type: "authorization_code",
       code: code,
       redirect_uri: redirect_uri,
       client_id: client_id,
       client_secret: client_secret
     })
     
     handle_token_response(response)
   end
   ```

4. **ID Token Validation**
   ```ruby
   # Method in Clavis::Providers::Base
   def validate_id_token(token, nonce: nil)
     decoded_token = decode_token(token)
     
     # Validate required claims
     validate_issuer(decoded_token)
     validate_audience(decoded_token)
     validate_expiration(decoded_token)
     validate_issued_at(decoded_token)
     validate_nonce(decoded_token, nonce) if nonce
     
     decoded_token
   end
   ```

### Provider-Specific Implementations

Each provider implements specific endpoints and requirements:

```ruby
# Example: Google Provider
module Clavis
  module Providers
    class Google < Base
      def authorization_endpoint
        "https://accounts.google.com/o/oauth2/v2/auth"
      end
      
      def token_endpoint
        "https://oauth2.googleapis.com/token"
      end
      
      def userinfo_endpoint
        "https://openidconnect.googleapis.com/v1/userinfo"
      end
      
      def default_scopes
        "openid email profile"
      end
      
      protected
      
      def process_userinfo_response(response)
        data = JSON.parse(response.body)
        {
          provider: "google",
          uid: data["sub"],
          info: {
            email: data["email"],
            email_verified: data["email_verified"],
            name: data["name"],
            first_name: data["given_name"],
            last_name: data["family_name"],
            image: data["picture"]
          }
        }
      end
    end
  end
end
```

### Error Handling

Clavis implements a structured error hierarchy for clear error handling:

```ruby
module Clavis
  # Base error class
  class Error < StandardError; end
  
  # Configuration errors
  class ConfigurationError < Error; end
  class ProviderNotConfigured < ConfigurationError; end
  class MissingConfiguration < ConfigurationError; end
  
  # Authentication errors
  class AuthenticationError < Error; end
  class InvalidState < AuthenticationError; end
  class MissingState < AuthenticationError; end
  class AuthorizationDenied < AuthenticationError; end
  
  # Token errors
  class TokenError < Error; end
  class InvalidToken < TokenError; end
  class ExpiredToken < TokenError; end
  class InvalidGrant < TokenError; end
  class InvalidAccessToken < TokenError; end
  
  # Provider errors
  class ProviderError < Error; end
  class UnsupportedProvider < ProviderError; end
  class ProviderAPIError < ProviderError; end
end
```

### Logging

Clavis integrates with Rails.logger to provide detailed logging for authentication events:

```ruby
module Clavis
  module Logging
    def self.log_authorization_request(provider, params)
      Rails.logger.info("[Clavis] Authorization request initiated for provider: #{provider}")
      Rails.logger.debug("[Clavis] Authorization parameters: #{params.except(:client_secret).inspect}")
    end
    
    def self.log_authorization_callback(provider, success)
      if success
        Rails.logger.info("[Clavis] Successful authorization callback from provider: #{provider}")
      else
        Rails.logger.warn("[Clavis] Failed authorization callback from provider: #{provider}")
      end
    end
    
    def self.log_token_exchange(provider, success)
      if success
        Rails.logger.info("[Clavis] Successful token exchange with provider: #{provider}")
      else
        Rails.logger.warn("[Clavis] Failed token exchange with provider: #{provider}")
      end
    end
    
    def self.log_error(error)
      Rails.logger.error("[Clavis] #{error.class}: #{error.message}")
      Rails.logger.debug("[Clavis] #{error.backtrace.join("\n")}")
    end
  end
end
```

## Usage Examples

### Basic Setup

```ruby
# Gemfile
gem 'clavis'

# Terminal
$ bundle install
$ rails g clavis:install --providers=google github

# config/initializers/clavis.rb
Clavis.configure do |config|
  config.providers = {
    google: {
      client_id: Rails.application.credentials.dig(:google, :client_id),
      client_secret: Rails.application.credentials.dig(:google, :client_secret),
      redirect_uri: "https://example.com/auth/google/callback"
    },
    github: {
      client_id: Rails.application.credentials.dig(:github, :client_id),
      client_secret: Rails.application.credentials.dig(:github, :client_secret),
      redirect_uri: "https://example.com/auth/github/callback"
    }
  }
end

# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
end

# Run migrations
$ rails db:migrate
```

### Accessing Standardized User Info

Clavis provides built-in helper methods for extracting standardized user information (email, name, avatar URL) from OAuth providers:

```ruby
# These helper methods are available on User model instances
# when the model includes Clavis::Models::OauthAuthenticatable

# Get user info from most recent OAuth provider
user.oauth_email       # => "user@example.com"
user.oauth_name        # => "John Doe"
user.oauth_avatar_url  # => "https://example.com/avatar.jpg"

# Get user info from a specific provider
user.oauth_email("google")       # => "user@example.com"
user.oauth_name("github")        # => "John Doe" 
user.oauth_avatar_url("facebook") # => "https://example.com/avatar.jpg"
```

These methods automatically normalize user information across different providers, handling the variations in how each provider structures their user data. This simplifies accessing common user attributes without needing provider-specific code.

The implementation uses a `UserInfoNormalizer` class internally to extract and standardize this information from the OAuth provider's response data stored in the `auth_data` field of the `OauthIdentity` model.

### Controller Integration

```ruby
# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController
  include Clavis::Controllers::Concerns::Authentication
  
  def create_from_oauth
    oauth_callback do |user, auth_hash|
      # Set up session
      session[:user_id] = user.id
      
      # Additional processing if needed
      if user.new_record?
        # User was just created
        redirect_to complete_profile_path
      else
        # User already existed
        redirect_to dashboard_path, notice: "Signed in successfully!"
      end
    end
  rescue Clavis::InvalidState
    redirect_to login_path, alert: "Authentication failed (invalid state)"
  rescue Clavis::AuthorizationDenied
    redirect_to login_path, alert: "You cancelled the authentication"
  rescue Clavis::TokenError => e
    Rails.logger.error("Token error: #{e.message}")
    redirect_to login_path, alert: "Authentication failed"
  end
end
```

### View Integration

```erb
<%# app/views/sessions/new.html.erb %>
<h1>Sign in</h1>

<%= form_with url: login_path, method: :post do |f| %>
  <div class="field">
    <%= f.label :email %>
    <%= f.email_field :email %>
  </div>
  
  <div class="field">
    <%= f.label :password %>
    <%= f.password_field :password %>
  </div>
  
  <div class="actions">
    <%= f.submit "Sign in" %>
  </div>
<% end %>

<div class="oauth-providers">
  <p>Or sign in with:</p>
  <%= clavis_oauth_button :google %>
  <%= clavis_oauth_button :github %>
  <%= clavis_oauth_button :apple %>
</div>
```

There are two ways to include the Clavis view helpers in your application:

#### Option 1: Manual Include (Recommended)

This approach avoids conflicts with Rails' built-in form helpers:

```ruby
# app/helpers/oauth_helper.rb
module OauthHelper
  include Clavis::ViewHelpers
end
```

Then in your view, reference the helper explicitly:

```erb
<%# Use the namespaced helper in your view %>
<%= clavis_oauth_button :google %>
<%= clavis_oauth_button :github, text: "Continue with GitHub" %>
```

#### Option 2: Auto-Include

Clavis can automatically include view helpers in your ApplicationHelper and ActionView, but this may conflict with Rails form helpers:

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  # ... other configuration
  
  # Enable automatic inclusion of view helpers (defaults to true)
  config.view_helpers_auto_include = true
end
```

### Customizing User Creation

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
  
  # Customize user creation from OAuth data
  def self.find_for_oauth(auth_hash)
    super do |user, auth|
      # Set additional user attributes based on the auth data
      user.name = auth[:info][:name]
      user.email = auth[:info][:email]
      user.avatar_url = auth[:info][:image] if user.respond_to?(:avatar_url)
    end
  end
end
```

### Customizing Button Appearance

```erb
<%# Custom button text %>
<%= oauth_button :google, text: "Continue with Google" %>

<%# Custom CSS class %>
<%= oauth_button :github, class: "my-custom-button" %>

<%# Custom data attributes %>
<%= oauth_button :apple, data: { analytics_event: "apple_login_click" } %>

<%# Completely custom button with same authorization flow %>
<%= link_to auth_path(:google), class: "my-fancy-button" do %>
  <i class="custom-icon"></i> Google Login
<% end %>
```

## Customization Guide

### Adding a New Provider

To add a custom OAuth provider:

```ruby
# lib/clavis/providers/custom_provider.rb
module Clavis
  module Providers
    class CustomProvider < Base
      def authorization_endpoint
        "https://custom-provider.com/oauth/authorize"
      end
      
      def token_endpoint
        "https://custom-provider.com/oauth/token"
      end
      
      def userinfo_endpoint
        "https://custom-provider.com/api/user"
      end
      
      def default_scopes
        "profile email"
      end
      
      protected
      
      def process_userinfo_response(response)
        data = JSON.parse(response.body)
        {
          provider: "custom_provider",
          uid: data["user_id"],
          info: {
            email: data["email"],
            name: data["display_name"],
            image: data["avatar_url"]
          }
        }
      end
    end
  end
end

# Register the provider
Clavis.register_provider(:custom_provider, Clavis::Providers::CustomProvider)
```

### Adding Custom Claims Processing

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  # Normal configuration...
  
  # Add custom claims processor
  config.claims_processor = proc do |auth_hash, user|
    # Process specific claims
    if auth_hash[:provider] == "google" && auth_hash[:info][:email_verified]
      user.verified_email = true
    end
    
    # Add roles based on provider or email domain
    if auth_hash[:info][:email].end_with?("@mycompany.com")
      user.add_role(:employee)
    end
    
    # Store additional provider data
    if auth_hash[:provider] == "github"
      user.github_username = auth_hash[:info][:nickname]
    end
  end
end
```

### Handling Error Responses

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  rescue_from Clavis::AuthenticationError do |exception|
    log_authentication_failure(exception)
    
    case exception
    when Clavis::InvalidState
      redirect_to login_path, alert: "Authentication session expired. Please try again."
    when Clavis::AuthorizationDenied
      redirect_to login_path, alert: "You cancelled the sign in process."
    else
      redirect_to login_path, alert: "Authentication failed: #{exception.message}"
    end
  end
  
  private
  
  def log_authentication_failure(exception)
    Rails.logger.warn("Authentication failure: #{exception.class} - #{exception.message}")
  end
end
```

## Advanced Topics

### Session Security

Since Clavis uses session-based authentication, it's important to configure Rails sessions properly:

```ruby
# config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store, 
  key: '_app_session',
  secure: Rails.env.production?, 
  httponly: true,
  expire_after: 2.weeks
```

### CSRF Protection

Clavis implements CSRF protection through the state parameter, but it's important to also maintain Rails' built-in CSRF protection:

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end
```

### Testing OAuth Integration

Example RSpec tests for OAuth integration:

```ruby
# spec/features/oauth_spec.rb
require 'rails_helper'

RSpec.describe "OAuth Authentication", type: :feature do
  before do
    OmniAuth.config.test_mode = true
    
    # Mock Google OAuth response
    OmniAuth.config.mock_auth[:google] = OmniAuth::AuthHash.new({
      provider: 'google',
      uid: '123456',
      info: {
        email: 'user@example.com',
        name: 'Test User',
        first_name: 'Test',
        last_name: 'User',
        image: 'https://example.com/avatar.jpg'
      },
      credentials: {
        token: 'mock_token',
        refresh_token: 'mock_refresh_token',
        expires_at: Time.now.to_i + 3600
      }
    })
  end
  
  scenario "User signs in with Google" do
    visit login_path
    
    click_link "Sign in with Google"
    
    expect(page).to have_content("Signed in successfully")
    expect(page).to have_content("Test User")
    
    # Verify user was created
    user = User.find_by(email: 'user@example.com')
    expect(user).not_to be_nil
    expect(user.oauth_identity_for('google')).to be_present
  end
end
```

## Troubleshooting Guide

### Common Issues

1. **Provider Not Configured Error**
   - **Symptoms**: "Provider 'google' not configured" error when trying to display or use a login button
   - **Solutions**:
     - Verify client_id and client_secret are set in credentials or environment variables
     - Check initializer configuration
     - Verify provider name spelling matches configuration

2. **Invalid Callback Error**
   - **Symptoms**: "Invalid redirect URI" or "redirect_uri_mismatch" error from provider
   - **Solutions**:
     - Verify the callback URI in your Clavis configuration EXACTLY matches what's registered in the provider dashboard
     - Common mistake: Using just the domain (e.g., `http://localhost:3000`) instead of full path (`http://localhost:3000/auth/google/callback`)
     - Check for protocol mismatches (http vs https)
     - Ensure port numbers are included if using non-standard ports
     - Different providers might have different requirements for trailing slashes
     - Some providers (like Google) may add extra query parameters to their callback validation, which should be ignored

3. **State Parameter Mismatch**
   - **Symptoms**: InvalidState error after returning from provider
   - **Solutions**:
     - Ensure cookies are enabled in the browser
     - Check session configuration
     - Verify user isn't using multiple tabs/windows for login

4. **Token Validation Failures**
   - **Symptoms**: InvalidToken errors after successful authorization
   - **Solutions**:
     - Check clock synchronization on server
     - Verify correct signing keys are being used
     - Check for token expiration issues

5. **View Helper Issues**
   - **Symptoms**: Undefined method `oauth_button` errors
   - **Solutions**:
     - Ensure `include Clavis::ViewHelpers` is in your ApplicationHelper
     - Check that the Clavis engine is properly mounted
     - Restart your Rails server to ensure initializers are loaded

### Integration with Existing Authentication

For issues integrating with existing authentication systems, see the detailed guide in `/docs/integration.md`.

## API Reference

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `providers` | Hash | `{}` | Provider configuration |
| `default_callback_path` | String | `/auth/:provider/callback` | Default callback path template |
| `default_scopes` | String | Provider-specific | Default OAuth scopes |
| `verbose_logging` | Boolean | `false` | Enable detailed logging |
| `claims_processor` | Proc | `nil` | Custom claims processing |

### Available Providers

| Provider | Key | Default Scopes | Notes |
|----------|-----|----------------|-------|
| Google | `:google` | `openid email profile` | Full OIDC support |
| GitHub | `:github` | `user:email` | Uses GitHub API for user info |
| Apple | `:apple` | `name email` | Requires special JWT client secret |
| Facebook | `:facebook` | `email public_profile` | Uses Graph API |
| Microsoft | `:microsoft` | `openid email profile` | Supports multi-tenant |

### Controller Concern Methods

| Method | Description | Parameters |
|--------|-------------|------------|
| `oauth_authorize` | Initiates OAuth flow | `provider`: The provider to use |
| `oauth_callback` | Handles OAuth callback | Block for custom handling |
| `find_or_create_user_from_oauth` | Maps auth data to user | `auth_hash`: Provider data |

### View Helper Methods

| Method | Description | Options |
|--------|-------------|---------|
| `clavis_oauth_button` | Renders OAuth button | `provider`: The provider to use<br>`text`: Custom button text<br>`class`: Additional CSS classes |
| `oauth_button` | Legacy alias for clavis_oauth_button | Same as above (maintained for backwards compatibility) |
| `clavis_provider_svg` | Renders provider logo | `provider`: The provider to use |
| `provider_svg` | Legacy alias for clavis_provider_svg | Same as above (maintained for backwards compatibility) |

### Auth Hash Structure

```ruby
{
  provider: "google",
  uid: "123456789",
  info: {
    email: "user@example.com",
    email_verified: true,
    name: "John Doe",
    first_name: "John",
    last_name: "Doe",
    image: "https://example.com/photo.jpg"
  },
  credentials: {
    token: "ACCESS_TOKEN",
    refresh_token: "REFRESH_TOKEN",
    expires_at: 1494520494,
    expires: true
  }
}
```

## Custom Providers

Clavis supports custom OAuth providers through two approaches:

1. Using the built-in Generic provider with configuration
2. Creating a custom provider class by extending the Base provider

### Generic Provider

The Generic provider allows you to configure any OAuth 2.0 provider by specifying the necessary endpoints:

```ruby
# In configuration
config.providers = {
  custom_provider: {
    client_id: ENV['CUSTOM_PROVIDER_CLIENT_ID'],
    client_secret: ENV['CUSTOM_PROVIDER_CLIENT_SECRET'],
    redirect_uri: 'https://your-app.com/auth/custom_provider/callback',
    authorization_endpoint: 'https://auth.custom-provider.com/oauth/authorize',
    token_endpoint: 'https://auth.custom-provider.com/oauth/token',
    userinfo_endpoint: 'https://api.custom-provider.com/userinfo',
    scopes: 'profile email',
    openid_provider: false
  }
}
```

The Generic provider implementation:

```ruby
module Clavis
  module Providers
    class Generic < Base
      attr_reader :auth_endpoint, :token_endpoint_url, :userinfo_endpoint_url, :scopes

      def initialize(config = {})
        @auth_endpoint = config[:authorization_endpoint]
        @token_endpoint_url = config[:token_endpoint]
        @userinfo_endpoint_url = config[:userinfo_endpoint]
        @scopes = config[:scopes]
        @is_openid = config[:openid_provider] || false

        validate_endpoints!
        super(config)
      end

      def authorization_endpoint
        @auth_endpoint
      end

      def token_endpoint
        @token_endpoint_url
      end

      def userinfo_endpoint
        @userinfo_endpoint_url
      end

      def default_scopes
        @scopes || ""
      end

      def openid_provider?
        @is_openid
      end

      protected

      def validate_endpoints!
        raise Clavis::MissingConfiguration.new("authorization_endpoint") if @auth_endpoint.nil? || @auth_endpoint.empty?
        raise Clavis::MissingConfiguration.new("token_endpoint") if @token_endpoint_url.nil? || @token_endpoint_url.empty?
        raise Clavis::MissingConfiguration.new("userinfo_endpoint") if @userinfo_endpoint_url.nil? || @userinfo_endpoint_url.empty?
      end
    end
  end
end
```

### Custom Provider Class

For more control, you can create your own provider class by extending `Clavis::Providers::Base`:

```ruby
module MyApp
  module Providers
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
```

### Registering Custom Providers

Register your custom provider with Clavis:

```ruby
# In an initializer
Clavis.register_provider(:example_oauth, MyApp::Providers::ExampleOAuth)
```

The provider registry is managed by the `Clavis` module:

```ruby
def register_provider(name, provider_class)
  provider_registry[name.to_sym] = provider_class
end

def provider_registry
  @provider_registry ||= {}
end
```

## Error Handling

Clavis provides a set of standardized error classes for handling different types of errors:

1. **ConfigurationError**: Errors related to configuration
2. **ProviderError**: Errors related to provider operations
3. **AuthorizationError**: Errors during the authorization process
4. **TokenError**: Errors related to token operations
5. **UserError**: Errors related to user operations

Each error class inherits from the base `Clavis::Error` class and provides specific error messages.

## Security Considerations

Clavis implements several security measures:

1. **State Parameter**: Prevents CSRF attacks by validating the state parameter
2. **Nonce Parameter**: Prevents replay attacks for OpenID Connect providers
3. **HTTPS**: Requires HTTPS for all OAuth operations
4. **Token Storage**: Securely stores tokens in the database
5. **Error Logging**: Logs security-related errors for monitoring

## Integration Points

Clavis integrates with Rails applications at several points:

1. **Routes**: Defines routes for OAuth authorization and callbacks
2. **Controllers**: Provides controller concerns for handling OAuth flows
3. **Models**: Provides model concerns for user creation and association
4. **Views**: Provides view helpers for generating OAuth buttons
5. **Database**: Stores OAuth identities and tokens
6. **Configuration**: Configures providers and options 