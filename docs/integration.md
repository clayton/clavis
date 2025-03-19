# Integrating Clavis with Existing Applications

This guide covers how to integrate Clavis with your existing Ruby on Rails application, particularly if you already have an authentication system in place.

## Table of Contents

1. [Overview](#overview)
2. [Database Setup](#database-setup)
3. [User Model Integration](#user-model-integration)
4. [Controller Integration](#controller-integration)
5. [View Integration](#view-integration)
6. [Route Configuration](#route-configuration)
7. [Working with Multiple Authentication Methods](#working-with-multiple-authentication-methods)
8. [Troubleshooting](#troubleshooting)

## Overview

Clavis is designed to work alongside your existing authentication system, providing OAuth/OIDC capabilities without replacing your current setup. This guide assumes you have an existing application with:

- A `User` model
- Some form of authentication (e.g., `has_secure_password`, Devise, etc.)
- Session management

## Database Setup

Clavis stores OAuth identities in a separate table with a polymorphic relationship to your user model.

1. **Run the installation generator**:

   ```bash
   rails generate clavis:install
   ```

2. **Review and run the migration**:

   ```bash
   rails db:migrate
   ```

   This creates a `clavis_oauth_identities` table with:
   
   ```ruby
   create_table :clavis_oauth_identities do |t|
     t.references :user, polymorphic: true, null: false, index: true
     t.string :provider, null: false
     t.string :uid, null: false
     t.json :auth_data
     t.string :token
     t.string :refresh_token
     t.datetime :expires_at
     t.timestamps
     
     t.index [:provider, :uid], unique: true
   end
   ```

## User Model Integration

Include the `OauthAuthenticatable` concern in your User model:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
  
  # Your existing authentication code (e.g., has_secure_password)
  
  # Optional: Customize how users are created/found from OAuth data
  def self.find_for_oauth(auth_hash)
    super do |user, auth|
      # Set additional attributes based on the OAuth data
      user.name = auth[:info][:name] if user.respond_to?(:name=)
      user.username = auth[:info][:nickname] if user.respond_to?(:username=)
      # You can access profile image with auth[:info][:image]
      # You can access email with auth[:info][:email]
    end
  end
end
```

## Controller Integration

You have a few options for controller integration:

### Option 1: Use your existing authentication controller

```ruby
# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController
  include Clavis::Controllers::Concerns::Authentication
  
  # Your existing login/logout actions...
  
  # Add OAuth callback handler
  def oauth_callback
    auth_hash = process_callback(params[:provider])
    
    # Find or create a user with the OAuth data
    @user = User.find_for_oauth(auth_hash)
    
    # Sign in the user (using your existing authentication system)
    session[:user_id] = @user.id
    
    redirect_to root_path, notice: "Signed in successfully!"
  rescue Clavis::AuthenticationError => e
    redirect_to login_path, alert: "Authentication failed: #{e.message}"
  end
  
  # Add OAuth authorization handler
  def oauth_authorize
    redirect_to auth_url(params[:provider])
  end
end
```

### Option 2: Generate a dedicated OAuth controller

```bash
rails generate clavis:controller Auth
```

This creates:
- `app/controllers/auth_controller.rb` with OAuth methods
- Views for login/etc.
- Routes for the OAuth flow

## View Integration

### Add OAuth buttons to your login form:

```erb
<%# app/views/sessions/new.html.erb %>
<h1>Sign In</h1>

<%# Your existing login form... %>

<div class="oauth-buttons">
  <p>Or sign in with:</p>
  <%= clavis_oauth_button :google %>
  <%= clavis_oauth_button :github %>
</div>
```

### Customize button appearance:

```erb
<%= clavis_oauth_button :google, text: "Continue with Google", class: "my-custom-button" %>
```

## Route Configuration

Add the necessary routes to your application:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  # Your existing routes...
  
  # OAuth routes
  get '/auth/:provider', to: 'sessions#oauth_authorize', as: :auth
  get '/auth/:provider/callback', to: 'sessions#oauth_callback'
end
```

## Working with Multiple Authentication Methods

When a user signs in with OAuth, you'll need to decide how to handle users who might already have password-based accounts:

### Email Matching Strategy

This is the default strategy in Clavis - when a user signs in with OAuth:

1. Clavis tries to find an existing `OauthIdentity` for the provider/uid
2. If not found, it looks for a user with a matching email address
3. If a user with matching email is found, it associates the OAuth identity with that user
4. If no user is found, it creates a new user and associates the OAuth identity

### Linking Accounts

You might want to allow users to link multiple OAuth providers to their account:

```ruby
# app/controllers/profiles_controller.rb
def link_oauth
  # Store the user_id in the session
  session[:linking_user_id] = current_user.id
  
  # Redirect to the OAuth provider
  redirect_to auth_path(params[:provider])
end

# app/controllers/sessions_controller.rb
def oauth_callback
  auth_hash = process_callback(params[:provider])
  
  # Check if we're linking an existing account
  if session[:linking_user_id].present?
    user = User.find(session[:linking_user_id])
    session.delete(:linking_user_id)
    
    # Find or create the identity
    identity = Clavis::OauthIdentity.find_or_initialize_by(
      provider: auth_hash[:provider],
      uid: auth_hash[:uid]
    )
    
    # Associate with the user
    identity.user = user
    identity.auth_data = auth_hash[:info]
    identity.token = auth_hash[:credentials][:token]
    identity.refresh_token = auth_hash[:credentials][:refresh_token]
    identity.expires_at = auth_hash[:credentials][:expires_at] ? Time.at(auth_hash[:credentials][:expires_at]) : nil
    identity.save!
    
    redirect_to edit_profile_path, notice: "Successfully linked #{params[:provider].capitalize} account"
  else
    # Normal login flow...
  end
end
```

## Troubleshooting

### View Helper Issues

If you're having trouble with the `clavis_oauth_button` helper, ensure your application helper includes Clavis's view helpers:

```ruby
# app/helpers/application_helper.rb
module ApplicationHelper
  include Clavis::ViewHelpers
  # ...
end
```

### Database Issues

If you see errors about the `clavis_oauth_identities` table, make sure you've run:

```bash
rails db:migrate
```

### Session Issues

If you're experiencing session-related issues:

1. Ensure you're not using `session.clear` which would remove Clavis's state parameters
2. Consider enabling session rotation in your Clavis configuration:

```ruby
Clavis.configure do |config|
  config.rotate_session_after_login = true
end
```

### Missing Routes

If you see errors about missing routes for OAuth buttons, ensure you've added:

```ruby
get '/auth/:provider', to: 'sessions#oauth_authorize', as: :auth
get '/auth/:provider/callback', to: 'sessions#oauth_callback'
```

### Security Concerns

For production environments, always ensure:

1. You're using HTTPS
2. Your OAuth provider credentials are properly secured (e.g., using Rails credentials)
3. You've configured allowed redirect hosts in Clavis configuration 