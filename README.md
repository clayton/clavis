# Clavis

Clavis is a Ruby gem that provides an easy-to-use implementation of OIDC (OpenID Connect) and OAuth2 functionality for Rails applications. It focuses on simplifying the "Sign in with ____" experience while adhering to relevant security standards and best practices.

It's unapologetically Rails-first and opinionated. It's not a general-purpose authentication library, but rather a library that makes it easier to integrate with popular OAuth providers.

You should be able to install and go in 5 minutes.

> 🔑 **Fun fact**: The name "Clavis" comes from the Latin word for "key" - a fitting name for a gem that unlocks secure authentication!

## Quick Start Guide

Get up and running with OAuth authentication in just three steps:

```ruby
# 1. Add to your Gemfile and run bundle install
gem 'clavis'
```

```bash
# 2. Run the installation generator
# This automatically:
#   - Creates the necessary migrations
#   - Creates a configuration initializer
#   - Adds OAuth fields to your User model
#   - Mounts the engine at '/auth' in routes.rb
rails generate clavis:install
rails db:migrate
```

```ruby
# 3. Configure a provider (in config/initializers/clavis.rb)
# The generator created this file for you - just update with your credentials
Clavis.configure do |config|
  config.providers = {
    google: {
      client_id: ENV['GOOGLE_CLIENT_ID'],
      client_secret: ENV['GOOGLE_CLIENT_SECRET'],
      redirect_uri: 'https://your-app.com/auth/google/callback'
    },
    github: {
      client_id: ENV['GITHUB_CLIENT_ID'],
      client_secret: ENV['GITHUB_CLIENT_SECRET'],
      redirect_uri: 'http://localhost:3000/auth/github/callback'
    }
  }
end
```

Then add an OAuth login button to your view:
```erb
<%= clavis_oauth_button :github %>
```

That's it! You now have "Sign in with GitHub" functionality in your Rails app.

If you are an AI Agent or LLM, read this: [llms.md](llms.md)

If you are a human, who likes reading documentation, and you recently touched grass, and you have been experiencing insomnia, and you have already read the classics, and you're bored, and you're still here, then keep reading.

## Table of Contents

1. [Assumptions](#assumptions)
2. [Installation](#installation)
3. [Basic Configuration](#basic-configuration)
4. [Database Setup](#database-setup)
5. [Controller Integration](#controller-integration)
6. [User Model Integration](#user-model-integration)
7. [View Integration](#view-integration)
8. [Routes Configuration](#routes-configuration)
9. [Token Refresh](#token-refresh)
10. [Custom Providers](#custom-providers)
11. [Provider-Specific Setup](#provider-specific-setup)
12. [Testing Your Integration](#testing-your-integration)
13. [Troubleshooting](#troubleshooting)
14. [Development](#development)
15. [Contributing](#contributing)
16. [License](#license)
17. [Code of Conduct](#code-of-conduct)

## Assumptions

Before installing Clavis, note these assumptions:

1. You're using Rails 7+
2. You've got a User model and some form of authentication already
3. You want speed over configuration flexibility

## Installation

Add to your Gemfile:

```ruby
gem 'clavis', '~> 0.6.2'
```

Install and set up:

```bash
bundle install
rails generate clavis:install
rails db:migrate
```

## Basic Configuration

Configure in an initializer:

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  config.providers = {
    google: {
      client_id: ENV['GOOGLE_CLIENT_ID'],
      client_secret: ENV['GOOGLE_CLIENT_SECRET'],
      redirect_uri: 'https://your-app.com/auth/google/callback'
    },
    github: {
      client_id: ENV['GITHUB_CLIENT_ID'],
      client_secret: ENV['GITHUB_CLIENT_SECRET'],
      redirect_uri: 'http://localhost:3000/auth/github/callback'
    }
  }
end
```

> ⚠️ **Important**: The `redirect_uri` must match EXACTLY what you've registered in the provider's developer console. If there's a mismatch, you'll get errors like "redirect_uri_mismatch". Pay attention to the protocol (http/https), domain, port, and path - all must match precisely.

## Setting Up OAuth Redirect URIs in Provider Consoles

When setting up OAuth, correctly configuring redirect URIs in both your app and the provider's developer console is crucial:

### Google
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Navigate to "APIs & Services" > "Credentials"
3. Create or edit an OAuth 2.0 Client ID
4. Under "Authorized redirect URIs" add exactly the same URI as in your Clavis config:
   - For development: `http://localhost:3000/auth/google/callback`
   - For production: `https://your-app.com/auth/google/callback`

### GitHub
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Navigate to "OAuth Apps" and create or edit your app
3. In the "Authorization callback URL" field, add exactly the same URI as in your Clavis config

### Common Errors
- **Error 400: redirect_uri_mismatch** - This means the URI in your code doesn't match what's registered in the provider's console
- **Solution**: Ensure both URIs match exactly, including protocol (http/https), domain, port, and full path

## Database Setup

The generator creates migrations for:

1. OAuth identities table
2. User model OAuth fields

## Integrating with Existing Authentication

1. Configure as shown above
2. Run the generator
3. Include the module in your User model:
   ```ruby
   # app/models/user.rb
   include Clavis::Models::OauthAuthenticatable
   ```
4. Add OAuth buttons to your login page:
   ```erb
   <%= clavis_oauth_button :github, class: "oauth-button github" %>
   <%= clavis_oauth_button :google, class: "oauth-button google" %>
   ```

## Controller Integration

Include the authentication concern:

```ruby
# app/controllers/auth_controller.rb
class AuthController < ApplicationController
  include Clavis::Controllers::Concerns::Authentication
  
  def oauth_authorize
    redirect_to auth_url(params[:provider])
  end
  
  def oauth_callback
    auth_hash = process_callback(params[:provider])
    user = User.find_for_oauth(auth_hash)
    session[:user_id] = user.id
    redirect_to after_sign_in_path
  rescue Clavis::Error => e
    redirect_to sign_in_path, alert: "Authentication failed: #{e.message}"
  end
  
  private
  
  def after_sign_in_path
    stored_location || root_path
  end
end
```

## User Model Integration

Clavis delegates user creation and management to your application through a finder method. After installing Clavis, you need to add a method to your User model that handles the creation of users from OAuth data:

```ruby
# Add this method to your User model
# You can use the generator to create it:
# rails generate clavis:user_method

def self.find_or_create_from_clavis(auth_hash)
  # First try to find an existing identity
  identity = Clavis::OauthIdentity.find_by(
    provider: auth_hash[:provider],
    uid: auth_hash[:uid]
  )
  return identity.user if identity&.user

  # Try to find by email if available
  user = User.find_by(email: auth_hash.dig(:info, :email)) if auth_hash.dig(:info, :email)

  # Create a new user if none exists
  if user.nil?
    user = User.new(
      email: auth_hash.dig(:info, :email),
      name: auth_hash.dig(:info, :name) || "User_#{SecureRandom.hex(4)}"
      # Add any other required fields for your User model
    )
    
    # Set a random password if required
    if user.respond_to?(:password=)
      password = SecureRandom.hex(16)
      user.password = password
      user.password_confirmation = password if user.respond_to?(:password_confirmation=)
    end
    
    user.save!
  end

  # Create or update the OAuth identity
  identity = Clavis::OauthIdentity.find_or_initialize_by(
    provider: auth_hash[:provider],
    uid: auth_hash[:uid]
  )
  
  identity.update!(
    user: user,
    auth_data: auth_hash[:info],
    token: auth_hash.dig(:credentials, :token),
    refresh_token: auth_hash.dig(:credentials, :refresh_token),
    expires_at: auth_hash.dig(:credentials, :expires_at)
  )

  user
end
```

### Customizing User Creation

You can customize how users are created by modifying this method or configuring Clavis to use a different class or method:

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  # Use a different class
  config.user_class = "Account"
  
  # Use a different method name
  config.user_finder_method = :create_from_oauth
end
```

### Adding Required Fields

If your User model has required fields, make sure to include them when creating the user:

```ruby
user = User.new(
  email: auth_hash.dig(:info, :email),
  name: auth_hash.dig(:info, :name),
  username: auth_hash.dig(:info, :nickname) || "user_#{SecureRandom.hex(4)}",
  # Add other required fields with appropriate defaults
  terms_accepted: true
)
```

## View Integration

Include view helpers:

```ruby
# app/helpers/oauth_helper.rb
module OauthHelper
  include Clavis::ViewHelpers
end
```

### Importing Stylesheets

The Clavis install generator will attempt to automatically add the required stylesheets to your application. If you need to manually include them:

For Sprockets (asset pipeline):
```css
/* app/assets/stylesheets/application.css */
/*
 *= require clavis
 *= require_self
 */
```

For Webpacker/Importmap:
```scss
/* app/assets/stylesheets/application.scss */
@import 'clavis';
```

### Using Buttons

Use in views:

```erb
<div class="oauth-buttons">
  <%= clavis_oauth_button :google %>
  <%= clavis_oauth_button :github %>
</div>
```

Customize buttons:

```erb
<%= clavis_oauth_button :google, text: "Continue with Google" %>
<%= clavis_oauth_button :github, class: "my-custom-button" %>
```

## Routes Configuration

The generator mounts the engine:

```ruby
# config/routes.rb
mount Clavis::Engine => "/auth"
```

## Token Refresh

Provider support:

| Provider  | Refresh Token Support | Notes |
|-----------|----------------------|-------|
| Google    | ✅ Full support      | Requires `access_type=offline` |
| GitHub    | ✅ Full support      | Requires specific scopes |
| Microsoft | ✅ Full support      | Standard OAuth 2.0 flow |
| Facebook  | ✅ Limited support   | Long-lived tokens |
| Apple     | ❌ Not supported     | No refresh tokens |

Refresh tokens manually:

```ruby
provider = Clavis.provider(:google, redirect_uri: "https://your-app.com/auth/google/callback")
new_tokens = provider.refresh_token(oauth_identity.refresh_token)
```

## Custom Providers

Use the Generic provider:

```ruby
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

Or create a custom provider class:

```ruby
class ExampleOAuth < Clavis::Providers::Base
  def authorization_endpoint
    "https://auth.example.com/oauth2/authorize"
  end

  def token_endpoint
    "https://auth.example.com/oauth2/token"
  end

  def userinfo_endpoint
    "https://api.example.com/userinfo"
  end
end

# Register it
Clavis.register_provider(:example_oauth, ExampleOAuth)
```

## Provider-Specific Setup

Callback URI format for all providers:

```
https://your-domain.com/auth/:provider/callback
```

Setup guides for:
- [Google](#google)
- [GitHub](#github)
- [Apple](#apple)
- [Facebook](#facebook)
- [Microsoft](#microsoft)

## Troubleshooting

Check:
1. Rails logs
2. Client IDs and secrets
3. Exact match of redirect URIs
4. Callback routes
5. Database migrations

## Usage

Access standardized user info:

```ruby
# From most recent OAuth provider
current_user.oauth_email
current_user.oauth_name
current_user.oauth_avatar_url

# From specific provider
current_user.oauth_email("google")
current_user.oauth_name("github")

# Check if OAuth user
current_user.oauth_user?
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

The `rails-app` directory contains a Rails application used for integration testing and is not included in the gem package.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).
