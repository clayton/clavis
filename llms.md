# Clavis: Large Language Model Documentation

This document provides technical information about the Clavis gem for large language models.

## Quick Start Guide for Implementation

Implement Clavis in three steps:

```ruby
# Step 1: Add to Gemfile
gem 'clavis'
```

```bash
# Step 2: Run the installation generator
rails generate clavis:install
rails db:migrate
```

```ruby
# Step 3: Configure a provider
Clavis.configure do |config|
  config.providers = {
    github: {
      client_id: ENV["GITHUB_CLIENT_ID"],
      client_secret: ENV["GITHUB_CLIENT_SECRET"]
    }
  }
  
  # Optional: Customize the path (default is '/auth/:provider/callback')
  # config.default_callback_path = '/oauth/:provider/callback'
end
```

### What the Generator Does

1. Creates migrations for OAuth identities
2. Mounts the engine at `/auth` 
3. Creates configuration initializer
4. Adds `Clavis::Models::OauthAuthenticatable` to User model

Add a button to your view:

```erb
<%= clavis_oauth_button :github %>
```

### Important Notes

1. Use the standard ERB syntax with `<%= %>` for OAuth buttons - the helper returns html_safe content
2. The gem automatically handles route setup when mounted at `/auth` - no additional route configuration needed
3. Always use the complete callback URI in provider configuration (e.g., `https://your-app.com/auth/github/callback`)
4. If you customize the mount path, make sure to update the `default_callback_path` configuration accordingly

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Implementation Details](#implementation-details)
5. [Usage Examples](#usage-examples)
6. [Customization Guide](#customization-guide)
7. [Error Handling](#error-handling)
8. [Security Considerations](#security-considerations)
9. [API Reference](#api-reference)
10. [Rate Limiting](#rate-limiting)

## Overview

Clavis implements OAuth 2.0 and OpenID Connect (OIDC) for Rails. It focuses on "Sign in with ____" functionality while maintaining security standards.

### Key Assumptions

1. Rails 7+ application
2. Existing User model and authentication
3. Speed over detailed configuration

## Architecture

### Core Components

1. **Configuration System** - Stores provider settings and validates configuration
2. **Provider Framework** - Implements OAuth/OIDC flows with provider-specific logic
3. **Authentication Flow** - Handles requests and callbacks with CSRF protection
4. **User Management** - Maps OAuth responses to user records
5. **View Components** - Button helpers with provider-specific styling
6. **Rails Integration** - Routes, generators, and existing auth integration

## Implementation Details

### Callback URI Format

Always use the complete callback URI:

```
https://your-domain.com/auth/:provider/callback
```

Common mistake: Using just the domain without the full path.

### Route Structure

The Clavis engine is mounted at `/auth` by default, which creates these routes:

```
/auth/google                - Start Google OAuth flow
/auth/google/callback       - Handle Google OAuth callback
/auth/:provider             - Generic provider route
/auth/:provider/callback    - Generic callback route
```

These routes are automatically registered when you mount the engine:

```ruby
# config/routes.rb (added by generator)
mount Clavis::Engine => "/auth"
```

#### Customizing the Path

You can customize the path in two ways:

1. **Change the engine mount point**:
```ruby
# config/routes.rb
mount Clavis::Engine => "/oauth"
```

2. **Update the callback path configuration**:
```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  # This should match your engine mount point
  config.default_callback_path = "/oauth/:provider/callback"
end
```

When customizing paths, make sure that:
1. The provider configuration's redirect URIs match your custom paths
2. Both the engine mount point and the `default_callback_path` are updated consistently

### OAuth Flow Implementation

1. **Authorization Request**
```ruby
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
def oauth_callback
  validate_state!(params[:state])
  auth_hash = provider.process_callback(params[:code], session.delete(:oauth_state))
  user = find_or_create_user_from_oauth(auth_hash)
  yield(user, auth_hash) if block_given?
end
```

3. **Token Exchange**
```ruby
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

### Provider Example: Google

```ruby
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
  
  def openid_provider?
    true
  end
  
  protected
  
  def process_userinfo_response(response)
    data = JSON.parse(response.body)
    
    # For OpenID Connect providers like Google, we use the sub claim
    # as the stable identifier. This is guaranteed to be unique and
    # consistent for each user, unlike other fields that might change.
    {
      provider: "google",
      uid: data["sub"], # sub is the stable identifier
      info: {
        email: data["email"],
        name: data["name"],
        image: data["picture"]
      }
    }
  end
end
```

### OpenID Connect vs OAuth2 Providers

Clavis handles two types of providers differently:

1. **OpenID Connect Providers** (e.g., Google)
   - Uses the `sub` claim as the stable identifier
   - This is guaranteed to be unique and consistent
   - Found in the ID token claims or userinfo response
   - Example: Google's `sub` is a stable numeric identifier

2. **OAuth2-only Providers** (e.g., GitHub)
   - Uses the provider's `uid` field
   - Identifier format varies by provider
   - Example: GitHub uses the user's numeric ID

When implementing a custom provider, use `openid_provider?` to indicate if it's an OpenID Connect provider:

```ruby
def openid_provider?
  true # for OIDC providers
  false # for OAuth2-only providers
end
```

## Usage Examples

### Basic Setup

```ruby
# Gemfile
gem 'clavis'

# Terminal
bundle install
rails g clavis:install

# config/initializers/clavis.rb
Clavis.configure do |config|
  config.providers = {
    google: {
      client_id: Rails.application.credentials.dig(:google, :client_id),
      client_secret: Rails.application.credentials.dig(:google, :client_secret),
      redirect_uri: "https://example.com/auth/google/callback"
    }
  }
end

# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
end
```

### Accessing User Info

```ruby
# Get user info from most recent OAuth provider
user.oauth_email       # => "user@example.com"
user.oauth_name        # => "John Doe"
user.oauth_avatar_url  # => "https://example.com/avatar.jpg"

# Get info from specific provider
user.oauth_email("google")
```

### Controller Integration

```ruby
class SessionsController < ApplicationController
  include Clavis::Controllers::Concerns::Authentication
  
  def create_from_oauth
    oauth_callback do |user, auth_hash|
      session[:user_id] = user.id
      redirect_to dashboard_path
    end
  rescue Clavis::AuthenticationError => e
    redirect_to login_path, alert: "Authentication failed"
  end
end
```

### View Integration

```erb
<div class="oauth-providers">
  <%= clavis_oauth_button :google %>
  <%= clavis_oauth_button :github %>
  <%= clavis_oauth_button :apple %>
</div>
```

Include view helpers:

```ruby
# app/helpers/oauth_helper.rb
module OauthHelper
  include Clavis::ViewHelpers
end
```

### Customizing Button Display

Clavis OAuth buttons can be customized with several options:

```erb
<!-- Custom text -->
<%= clavis_oauth_button :google, text: "Continue with Google" %>

<!-- Custom CSS class -->
<%= clavis_oauth_button :github, class: "my-custom-button" %>

<!-- Custom HTML attributes -->
<%= clavis_oauth_button :apple, html: { data: { turbo: false } } %>
```

The buttons are rendered with HTML-safe content, so you can use the standard ERB output tag `<%= %>` without extra escaping.

## Customization Guide

### Adding a Custom Provider

```ruby
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
end

# Register the provider
Clavis.register_provider(:custom_provider, CustomProvider)
```

### Custom Claims Processing

```ruby
config.claims_processor = proc do |auth_hash, user|
  # Set verified email if from Google
  if auth_hash[:provider] == "google" && auth_hash[:info][:email_verified]
    user.verified_email = true
  end
  
  # Add role based on email domain
  if auth_hash[:info][:email].end_with?("@mycompany.com")
    user.add_role(:employee)
  end
end
```

## Security Considerations

Clavis implements several security features:

1. **State Parameter** - Prevents CSRF attacks
2. **Nonce Parameter** - Prevents replay attacks for OIDC
3. **HTTPS** - Required for OAuth operations
4. **Secure Token Storage** - Encrypted in database
5. **Error Logging** - Security events monitoring

### Rate Limiting

Clavis integrates with Rack::Attack to protect OAuth endpoints against DDoS and brute force attacks.

```ruby
# Rate limiting is enabled by default
Clavis.configure do |config|
  config.rate_limiting_enabled = true
  
  # Optional: Configure custom throttles
  config.custom_throttles = {
    "login_page": {
      limit: 30,
      period: 1.minute,
      block: ->(req) { req.path == "/login" ? req.ip : nil }
    }
  }
end
```

#### Default Rate Limits

By default, Clavis applies these rate limits:

1. **Authorization Endpoints**: 20 requests per minute per IP address
2. **Callback Endpoints**: 15 requests per minute per IP address
3. **Login Attempts by Email**: 5 requests per 20 seconds per email address

#### Integration Details

1. Clavis uses Rack::Attack middleware
2. Rate limiting is automatically configured when the gem is loaded
3. No additional gem installation required (Rack::Attack is a dependency)
4. Uses Rails cache for throttle storage by default

#### Custom Configuration

For advanced customization, create a dedicated Rack::Attack configuration:

```ruby
# config/initializers/rack_attack.rb
Rack::Attack.throttle("custom/auth", limit: 10, period: 30.seconds) do |req|
  req.ip if req.path =~ %r{/auth/}
end

# Dedicated cache store for rate limiting
Rack::Attack.cache.store = ActiveSupport::Cache::RedisCacheStore.new(
  url: ENV["REDIS_RATE_LIMIT_URL"]
)
```

#### Implementation Notes

1. Rate limiting middleware installation happens in `Clavis::Engine`
2. Throttle rules are defined in `Clavis::Security::RateLimiter`
3. Configuration via `rate_limiting_enabled` and `custom_throttles` in Clavis config
4. When disabled, no middleware is added and there's zero performance impact

## API Reference

### Available Providers

| Provider | Key | Default Scopes | Notes |
|----------|-----|----------------|-------|
| Google | `:google` | `openid email profile` | Full OIDC support |
| GitHub | `:github` | `user:email` | Uses GitHub API |
| Apple | `:apple` | `name email` | JWT client secret |
| Facebook | `:facebook` | `email public_profile` | Uses Graph API |
| Microsoft | `:microsoft` | `openid email profile` | Multi-tenant |

### Auth Hash Structure

```ruby
{
  provider: "google",
  uid: "123456789",
  info: {
    email: "user@example.com",
    email_verified: true,
    name: "John Doe",
    image: "https://example.com/photo.jpg"
  },
  credentials: {
    token: "ACCESS_TOKEN",
    refresh_token: "REFRESH_TOKEN",
    expires_at: 1494520494
  }
}
``` 