# Clavis: API Documentation for LLM Integration

This document provides structured technical information about the Clavis gem for large language models and AI assistants. It's designed to be a comprehensive reference for automated code generation and assistance with Clavis OAuth integration.

## Reference Index

- [Quick Start](#quick-start-reference) - Minimal implementation steps
- [Installation](#installation-details) - What the generator creates
- [Configuration](#required-configuration) - Setting up providers
- [User Creation](#critical-step-customize-user-creation) - Required customization
- [Auth Routes](#core-routes) - Automatic route setup
- [Auth Hash](#auth-hash-structure) - OAuth data structure
- [Controllers](#controller-example) - Controller integration
- [Views](#view-integration) - Button rendering
- [Password Integration](#password-integration) - has_secure_password handling
- [Providers](#available-providers) - Supported OAuth providers
- [Custom Providers](#custom-provider-example) - Creating custom providers
- [Error Handling](#common-errors-and-solutions) - Troubleshooting common issues
- [Security](#security-features) - Security implementation details
- [Environment Variables](#environment-variables-summary) - Required environment variables

## Quick Start Reference

```ruby
# Step 1: Add to Gemfile
gem 'clavis'

# Step 2: Run installation
rails generate clavis:install
rails db:migrate

# Step 3: Configure provider
Clavis.configure do |config|
  config.providers = {
    github: {
      client_id: ENV["GITHUB_CLIENT_ID"],
      client_secret: ENV["GITHUB_CLIENT_SECRET"],
      redirect_uri: "https://your-app.com/auth/github/callback"
    }
  }
end

# Step 4: Add button to view
<%= clavis_oauth_button :github %>

# Step 5: CRITICAL - Customize user creation
# Edit app/models/concerns/clavis_user_methods.rb
```

## Installation Details

The generator automatically:
1. Creates migrations for OAuth identities
2. Mounts the engine at `/auth` 
3. Creates configuration initializer
4. Adds `Clavis::Models::OauthAuthenticatable` to User model
5. Creates a ClavisUserMethods concern for user creation

### Required Configuration

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  config.providers = {
    google: {
      client_id: ENV["GOOGLE_CLIENT_ID"],
      client_secret: ENV["GOOGLE_CLIENT_SECRET"],
      redirect_uri: "https://your-app.com/auth/google/callback"
    }
  }
end
```

### Auth Callback URI Configuration

Always use the complete callback URI in both Clavis config and provider developer console:

```
https://your-domain.com/auth/:provider/callback
```

Common error: `redirect_uri_mismatch` - caused by URI mismatch between your code and provider console settings.

### Core Routes

```
/auth/:provider             - Initiates OAuth flow
/auth/:provider/callback    - Handles OAuth callback
```

These routes are automatically registered via:

```ruby
# config/routes.rb (added by generator)
mount Clavis::Engine => "/auth"
```

## Critical Step: Customize User Creation

You MUST customize the user creation code to include all required fields for your User model:

```ruby
# app/models/concerns/clavis_user_methods.rb
def find_or_create_from_clavis(auth_hash)
  # First try to find existing identity...
  
  # Create new user if none exists
  if user.nil?
    # Convert to HashWithIndifferentAccess for reliable key access
    info = auth_hash[:info].with_indifferent_access if auth_hash[:info]
    
    user = new(
      email: info&.dig(:email),
      # Add your required User model fields here:
      first_name: info&.dig(:given_name) || info&.dig(:first_name),
      last_name: info&.dig(:family_name) || info&.dig(:last_name),
      username: info&.dig(:nickname) || "user_#{SecureRandom.hex(4)}",
      avatar_url: info&.dig(:picture) || info&.dig(:image),
      terms_accepted: true  # For required boolean fields
    )
    
    # Mark this user for password validation skipping
    user.skip_password_validation = true
    user.save!
  end
  
  # Create identity and return user...
end
```

## Auth Hash Structure

The `auth_hash` contains standardized OAuth data from providers:

```ruby
{
  provider: "google",        # Provider name (string)
  uid: "123456789",          # Unique user ID (string)
  
  info: {                    # User information
    email: "user@example.com",
    email_verified: true,    # Only from OIDC providers
    name: "John Doe",
    given_name: "John",      # From Google/OIDC
    family_name: "Doe",      # From Google/OIDC
    first_name: "John",      # From some OAuth2 providers
    last_name: "Doe",        # From some OAuth2 providers
    nickname: "johndoe",     # Usually from GitHub
    picture: "https://...",  # From Google/OIDC
    image: "https://...",    # From OAuth2 providers
    urls: {                  # Provider-specific profile URLs
      website: "https://...",
      profile: "https://..."
    }
  },
  
  credentials: {             # OAuth tokens
    token: "ACCESS_TOKEN",
    refresh_token: "REFRESH_TOKEN",
    expires_at: 1494520494,  # Unix timestamp
    expires: true            # Whether token expires
  },
  
  id_token_claims: {         # OpenID Connect claims (Google, Microsoft)
    sub: "123456789",        # Stable unique identifier
    email: "user@example.com",
    email_verified: true,
    name: "John Doe",
    picture: "https://..."
  },
  
  extra: {                   # Additional provider data
    raw_info: { /* Raw provider response */ }
  }
}
```

### Accessing User Info

```ruby
# Get info from most recent OAuth provider
user.oauth_email       # => "user@example.com"
user.oauth_name        # => "John Doe"
user.oauth_avatar_url  # => "https://example.com/avatar.jpg"

# Get info from specific provider
user.oauth_email("google")
user.oauth_name("github")

# Check if OAuth user
user.oauth_user?       # => true/false
```

## Provider Integration Examples

### Controller Example

```ruby
class SessionsController < ApplicationController
  include Clavis::Controllers::Concerns::Authentication
  
  def create_from_oauth
    oauth_callback do |user, auth_hash|
      session[:user_id] = user.id
      redirect_to dashboard_path
    end
  rescue Clavis::AuthenticationError => e
    redirect_to login_path, alert: "Authentication failed: #{e.message}"
  end
end
```

### View Integration

```erb
<!-- Basic buttons -->
<%= clavis_oauth_button :google %>
<%= clavis_oauth_button :github %>

<!-- Customized buttons -->
<%= clavis_oauth_button :google, text: "Continue with Google" %>
<%= clavis_oauth_button :github, class: "my-custom-button" %>
<%= clavis_oauth_button :apple, html: { data: { turbo: false } } %>
```

## Available Providers

| Provider   | Key        | Scopes                | Identifier Strategy   | Notes |
|------------|------------|------------------------|----------------------|-------|
| Google     | `:google`  | `openid email profile` | OIDC `sub` claim     | Full OIDC support |
| GitHub     | `:github`  | `user:email`           | OAuth2 `uid`         | Uses GitHub API |
| Apple      | `:apple`   | `name email`           | OIDC `sub` claim     | JWT client secret |
| Facebook   | `:facebook`| `email public_profile` | OAuth2 `uid`         | Uses Graph API |
| Microsoft  | `:microsoft`| `openid email profile` | OIDC `sub` claim     | Multi-tenant support |

## Password Integration

For User models with `has_secure_password`, handle password validation:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include ClavisUserMethods
  has_secure_password
  
  # Option 1: Skip validation for OAuth users (recommended)
  validates :password, presence: true, 
    unless: -> { skip_password_validation }, on: :create
    
  # Option 2: Set random password for OAuth users
  before_validation :set_random_password,
    if: -> { skip_password_validation && respond_to?(:password=) }
    
  private
  
  def set_random_password
    self.password = SecureRandom.hex(16)
    self.password_confirmation = password if respond_to?(:password_confirmation=)
  end
end
```

## Common Errors and Solutions

| Error | Cause | Solution | Code Example |
|-------|-------|----------|--------------|
| `redirect_uri_mismatch` | URI in code doesn't match provider console | Make URIs identical (protocol, domain, port, path) | Check both provider config and console settings |
| `invalid_client` | Client ID/secret incorrect | Check provider credentials in config | Verify ENV variables are correctly set |
| `User validation failed` | Required fields missing | Customize user creation with required fields | See [User Creation](#critical-step-customize-user-creation) |
| `Password can't be blank` | Password validation for OAuth users | Implement validation skipping for OAuth users | See [Password Integration](#password-integration) |
| `unknown provider` | Provider not configured | Add provider to configuration | Add to `config.providers` hash |
| `undefined method user for nil` | OAuth identity not associated with user | Fix user creation process | Check `find_or_create_from_clavis` implementation |

## Error Handling Implementation

```ruby
# In your controllers
def oauth_callback
  begin
    # Standard OAuth flow
    auth_hash = process_callback(params[:provider])
    user = User.find_or_create_from_clavis(auth_hash)
    sign_in_user(user)
    redirect_to after_sign_in_path
  rescue Clavis::Error => e
    case e.message
    when /redirect_uri_mismatch/
      redirect_to sign_in_path, alert: "OAuth configuration error. Please contact support."
    when /invalid_client/
      redirect_to sign_in_path, alert: "Authentication service unavailable."
    when /unknown provider/
      redirect_to sign_in_path, alert: "This login method is not available."
    else
      redirect_to sign_in_path, alert: "Authentication failed: #{e.message}"
    end
  end
end
```

## Custom Provider Example

```ruby
# config/initializers/clavis.rb
class CustomProvider < Clavis::Providers::Base
  def authorization_endpoint
    "https://auth.custom-provider.com/oauth/authorize"
  end
  
  def token_endpoint
    "https://auth.custom-provider.com/oauth/token"
  end
  
  def userinfo_endpoint
    "https://api.custom-provider.com/userinfo"
  end
  
  def default_scopes
    "email profile"
  end
  
  def openid_provider?
    false  # true for OIDC providers
  end
end

# Register provider
Clavis.register_provider(:custom_provider, CustomProvider)

# Configure provider
Clavis.configure do |config|
  config.providers = {
    custom_provider: {
      client_id: ENV["CUSTOM_CLIENT_ID"],
      client_secret: ENV["CUSTOM_CLIENT_SECRET"],
      redirect_uri: "https://your-app.com/auth/custom_provider/callback"
    }
  }
end
```

## OpenID Connect vs OAuth2

| Feature | OIDC Providers (Google, Microsoft, Apple) | OAuth2 Providers (GitHub, Facebook) |
|---------|-------------------------------------------|-------------------------------------|
| User identifier | `sub` claim (stable, guaranteed unique) | `uid` field (provider-specific) |
| Email verification | Provides `email_verified` claim | Usually not available |
| User info format | Standardized claims | Varies by provider |
| ID tokens | Provides JWT ID tokens | Not available |
| Access method | `auth_hash[:id_token_claims][:sub]` | `auth_hash[:uid]` |
| Example providers | Google, Microsoft, Apple | GitHub, Facebook |

## Security Features

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| CSRF Protection | State parameter | Prevents cross-site request forgery |
| Replay Prevention | Nonce parameter | Prevents token replay attacks |
| Transport Security | HTTPS requirement | Ensures secure data transmission |
| Token Encryption | Database encryption | Protects stored tokens |
| Rate Limiting | Request throttling | Protects against brute force/DDoS |

### Rate Limiting Configuration

```ruby
# Enabled by default with these rate limits:
# - Auth endpoints: 20 requests/minute per IP
# - Callback endpoints: 15 requests/minute per IP
# - Login attempts: 5 requests/20 seconds per email

# Custom configuration
Clavis.configure do |config|
  config.rate_limiting_enabled = true
  config.custom_throttles = {
    "login_page": {
      limit: 30,
      period: 1.minute,
      block: ->(req) { req.path == "/login" ? req.ip : nil }
    }
  }
end
```

## Environment Variables Summary

| Variable | Purpose | Format | Required |
|----------|---------|--------|----------|
| GOOGLE_CLIENT_ID | Google OAuth | String | For Google auth |
| GOOGLE_CLIENT_SECRET | Google OAuth | String | For Google auth |
| GITHUB_CLIENT_ID | GitHub OAuth | String | For GitHub auth |
| GITHUB_CLIENT_SECRET | GitHub OAuth | String | For GitHub auth |
| APPLE_CLIENT_ID | Apple OAuth | String | For Apple auth |
| APPLE_CLIENT_SECRET | Apple OAuth | JWT/PEM | For Apple auth |
| FACEBOOK_CLIENT_ID | Facebook OAuth | String | For Facebook auth |
| FACEBOOK_CLIENT_SECRET | Facebook OAuth | String | For Facebook auth |
| MICROSOFT_CLIENT_ID | Microsoft OAuth | String | For Microsoft auth |
| MICROSOFT_CLIENT_SECRET | Microsoft OAuth | String | For Microsoft auth | 