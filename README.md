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
    github: {
      client_id: ENV["GITHUB_CLIENT_ID"],
      client_secret: ENV["GITHUB_CLIENT_SECRET"]
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

> ⚠️ **Important**: Always use the complete callback URI including the provider path (`/auth/:provider/callback`).

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

The generator adds fields to your User model and includes the `OauthAuthenticatable` module.

For manual integration:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
  
  # Optional: Skip password validation for OAuth users
  def password_required?
    !oauth_user?
  end
end
```

Customize user creation:

```ruby
# app/models/user.rb
def self.find_for_oauth(auth_hash)
  super do |user, auth|
    user.name = auth[:info][:name]
    user.email = auth[:info][:email]
    user.avatar_url = auth[:info][:picture] if user.respond_to?(:avatar_url)
  end
end
```

## View Integration

Include view helpers:

```ruby
# app/helpers/oauth_helper.rb
module OauthHelper
  include Clavis::ViewHelpers
end
```

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
