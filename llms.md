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
end
```

### What the Generator Does

1. Creates migrations for OAuth identities
2. Mounts the engine at `/auth` 
3. Creates configuration initializer
4. Adds `Clavis::Models::OauthAuthenticatable` to User model

Add a button to your view:

```erb
<%= link_to "Sign in with GitHub", auth_path(:github), class: "button" %>
```

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
  
  protected
  
  def process_userinfo_response(response)
    data = JSON.parse(response.body)
    {
      provider: "google",
      uid: data["sub"],
      info: {
        email: data["email"],
        name: data["name"],
        image: data["picture"]
      }
    }
  end
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

### Customizing User Creation

```ruby
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
  
  def self.find_for_oauth(auth_hash)
    super do |user, auth|
      user.name = auth[:info][:name]
      user.email = auth[:info][:email]
    end
  end
end
```

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