# Clavis - LLM Documentation

This document provides detailed information about the Clavis gem architecture, implementation details, and usage patterns. It is designed to be consumed by Large Language Models to assist developers with implementation and customization.

## Overview

Clavis is a Ruby gem that implements the OAuth 2.0 and OpenID Connect (OIDC) protocols for Rails applications. It focuses on providing a simple "Sign in with ____" experience while maintaining security and adherence to relevant specifications.

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
   - Support for handling multiple providers per user (future)

5. **View Components**
   - Button helpers with SVG icons for popular providers
   - Customizable styling and text
   - Validation to prevent display of unconfigured providers

6. **Rails Integration**
   - Rails engine for routes and assets
   - Generators for controllers, views, and migrations
   - Seamless integration with Rails 8 authentication

## Implementation Details

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
  <%= oauth_button :google %>
  <%= oauth_button :github %>
  <%= oauth_button :apple %>
</div>
```

### Customizing User Creation

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
  
  # Override the default behavior
  def self.find_for_oauth(auth_hash)
    # Find user by provider/uid or email
    user = find_by(provider: auth_hash[:provider], uid: auth_hash[:uid]) || 
           find_by(email: auth_hash[:info][:email])
    
    if user.nil?
      # Create a new user
      user = new(
        provider: auth_hash[:provider],
        uid: auth_hash[:uid],
        email: auth_hash[:info][:email],
        name: auth_hash[:info][:name],
        password: SecureRandom.hex(20) # Generate a secure random password
      )
      
      # Add any additional user setup
      user.skip_confirmation! if user.respond_to?(:skip_confirmation!)
      user.save!
      
      # Create user profile
      UserProfile.create!(
        user: user,
        avatar_url: auth_hash[:info][:image],
        display_name: auth_hash[:info][:nickname] || auth_hash[:info][:name]
      )
    elsif user.provider.nil? || user.uid.nil?
      # Existing user is connecting an OAuth account for the first time
      user.update!(
        provider: auth_hash[:provider],
        uid: auth_hash[:uid]
      )
    end
    
    user
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
<%= link_to auth_authorize_path(:google), class: "my-fancy-button" do %>
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
    expect(user.provider).to eq('google')
    expect(user.uid).to eq('123456')
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
   - **Symptoms**: "Invalid callback URL" error from provider
   - **Solutions**:
     - Verify redirect_uri matches exactly what is configured in provider dashboard
     - Check for http vs https mismatch
     - Ensure the callback URL is registered with the provider

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

### Logging Guidance

To debug authentication issues, enable detailed logging:

```ruby
# config/environments/development.rb
Rails.application.configure do
  config.log_level = :debug
end

# config/initializers/clavis.rb
Clavis.configure do |config|
  config.verbose_logging = true
end
```

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
| `oauth_button` | Renders OAuth button | `provider`: The provider to use<br>`text`: Custom button text<br>`class`: Additional CSS classes |
| `provider_svg` | Renders provider logo | `provider`: The provider to use |

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