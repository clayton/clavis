# Clavis

Clavis is a Ruby gem that provides an easy-to-use implementation of OIDC (OpenID Connect) and OAuth2 functionality for Rails applications. It focuses on simplifying the "Sign in with ____" experience while adhering to relevant security standards and best practices.

## Table of Contents

1. [Installation](#installation)
2. [Basic Configuration](#basic-configuration)
3. [Database Setup](#database-setup)
4. [Controller Integration](#controller-integration)
5. [User Model Integration](#user-model-integration)
6. [View Integration](#view-integration)
7. [Routes Configuration](#routes-configuration)
8. [Token Refresh](#token-refresh)
9. [Custom Providers](#custom-providers)
   - [Using the Generic Provider](#using-the-generic-provider)
   - [Creating a Custom Provider Class](#creating-a-custom-provider-class)
   - [Registering Custom Providers](#registering-custom-providers)
10. [Provider-Specific Setup](#provider-specific-setup)
    - [Google](#google)
    - [GitHub](#github)
    - [Apple](#apple)
    - [Facebook](#facebook)
    - [Microsoft](#microsoft)
11. [Testing Your Integration](#testing-your-integration)
12. [Troubleshooting](#troubleshooting)
13. [Development](#development)
14. [Contributing](#contributing)
15. [License](#license)
16. [Code of Conduct](#code-of-conduct)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'clavis', '~> 0.2.0'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install clavis
```

Generate the necessary migrations:

```bash
rails generate clavis:install
```

Run the migrations:

```bash
rails db:migrate
```

## Basic Configuration

Configure Clavis in an initializer:

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  # Configure your OAuth providers here
  config.providers = {
    google: {
      client_id: ENV['GOOGLE_CLIENT_ID'],
      client_secret: ENV['GOOGLE_CLIENT_SECRET'],
      redirect_uri: 'https://your-app.com/auth/google/callback'
    },
    github: {
      client_id: ENV['GITHUB_CLIENT_ID'],
      client_secret: ENV['GITHUB_CLIENT_SECRET'],
      redirect_uri: 'https://your-app.com/auth/github/callback'
    }
    # Add other providers as needed
  }
  
  # Optional: Configure logging
  config.logger = Rails.logger
  config.log_level = :info
end
```

## Database Setup

Clavis requires a table to store OAuth identities. The migration should have created a table like this:

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

## Integrating with Existing Authentication

If you already have an authentication system in your application, follow these steps to integrate Clavis:

1. **Configure Clavis** as shown in the Basic Configuration section.

2. **Run the installation generator**:
   ```bash
   rails generate clavis:install
   rails db:migrate
   ```

3. **Include the OauthAuthenticatable module** in your User model:
   ```ruby
   # app/models/user.rb
   class User < ApplicationRecord
     include Clavis::Models::OauthAuthenticatable
     
     # Your existing authentication code
     has_secure_password
     
     # Optional: Customize how OAuth users are created/found
     def self.find_for_oauth(auth_hash)
       super do |user, auth|
         # Set additional user attributes from auth data
         user.name = auth[:info][:name] if user.respond_to?(:name=)
         # Any other attribute assignments...
       end
     end
   end
   ```

4. **Create or modify your authentication controller**:
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
   end
   ```

5. **Add routes for OAuth authentication**:
   ```ruby
   # config/routes.rb
   Rails.application.routes.draw do
     # Your existing routes...
     
     # OAuth routes
     get '/auth/:provider', to: 'sessions#oauth_authorize', as: :auth
     get '/auth/:provider/callback', to: 'sessions#oauth_callback'
   end
   ```

6. **Add OAuth buttons to your login page**:
   ```erb
   <%# app/views/sessions/new.html.erb %>
   <h1>Sign In</h1>
   
   <%# Your existing login form... %>
   
   <div class="oauth-buttons">
     <p>Or sign in with:</p>
     <%= oauth_button :google %>
     <%= oauth_button :github %>
   </div>
   ```

## Controller Integration

Include the authentication concern in your controller:

```ruby
# app/controllers/auth_controller.rb
class AuthController < ApplicationController
  include Clavis::Controllers::Concerns::Authentication
  
  # Initiates the OAuth flow
  def oauth_authorize
    redirect_to auth_url(params[:provider])
  end
  
  # Handles the OAuth callback
  def oauth_callback
    auth_hash = process_callback(params[:provider])
    
    # Find or create a user based on the OAuth data
    user = User.find_for_oauth(auth_hash)
    
    # Sign in the user
    session[:user_id] = user.id
    
    # Redirect to the appropriate page
    redirect_to after_sign_in_path, notice: "Successfully signed in with #{params[:provider].capitalize}"
  rescue Clavis::Error => e
    # Handle authentication errors
    Rails.logger.error("OAuth error: #{e.message}")
    redirect_to sign_in_path, alert: "Authentication failed: #{e.message}"
  end
  
  private
  
  def after_sign_in_path
    stored_location || root_path
  end
  
  def stored_location
    session.delete(:return_to)
  end
end
```

## User Model Integration

Include the OAuth authenticatable concern in your User model:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::Concerns::OauthAuthenticatable
  
  # Optional: Customize user creation
  def self.find_for_oauth(auth_hash)
    super do |user, auth|
      # Set additional user attributes based on the auth data
      user.name = auth[:info][:name]
      user.email = auth[:info][:email]
      user.avatar_url = auth[:info][:picture] if user.respond_to?(:avatar_url)
    end
  end
end
```

## View Integration

Include the view helpers in your application helper:

```ruby
# app/helpers/application_helper.rb
module ApplicationHelper
  include Clavis::ViewHelpers
end
```

Add OAuth buttons to your sign-in page:

```erb
<%# app/views/sessions/new.html.erb %>
<h1>Sign In</h1>

<div class="oauth-buttons">
  <%= oauth_button :google %>
  <%= oauth_button :github %>
  <%= oauth_button :apple %>
  <%= oauth_button :facebook %>
  <%= oauth_button :microsoft %>
</div>

<%# Or with custom text %>
<div class="oauth-buttons">
  <%= oauth_button :google, text: "Continue with Google" %>
</div>

<%# Or with custom classes %>
<div class="oauth-buttons">
  <%= oauth_button :github, class: "my-custom-button" %>
</div>
```

## Routes Configuration

Add the necessary routes to your application:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  # OAuth routes
  get '/auth/:provider', to: 'auth#oauth_authorize', as: :auth
  get '/auth/:provider/callback', to: 'auth#oauth_callback'
  
  # Other routes...
end
```

## Token Refresh

### Overview

OAuth 2.0 access tokens typically have a limited lifespan. When they expire, your application needs to obtain new tokens to continue accessing protected resources. The token refresh mechanism allows you to request new access tokens using a refresh token that was provided during the initial authentication.

### Provider Support

Not all OAuth providers support refresh tokens. Here's the current support status in Clavis:

| Provider  | Refresh Token Support | Notes |
|-----------|----------------------|-------|
| Google    | ✅ Full support      | Requires `access_type=offline` parameter |
| GitHub    | ✅ Full support      | Requires specific scopes |
| Microsoft | ✅ Full support      | Standard OAuth 2.0 refresh flow |
| Facebook  | ✅ Limited support   | Long-lived tokens with extended expiration |
| Apple     | ❌ Not supported     | Apple doesn't provide refresh tokens |

### Refreshing Tokens Manually

You can refresh tokens manually using the provider instance:

```ruby
# Get the provider instance
provider = Clavis.provider(:google, redirect_uri: "https://your-app.com/auth/google/callback")

# Refresh the token
begin
  new_tokens = provider.refresh_token(oauth_identity.refresh_token)
  
  # Update the OAuth identity with new tokens
  oauth_identity.update(
    token: new_tokens[:access_token],
    refresh_token: new_tokens[:refresh_token] || oauth_identity.refresh_token,
    expires_at: Time.at(new_tokens[:expires_at])
  )
rescue Clavis::TokenError => e
  # Handle refresh token errors
  Rails.logger.error("Failed to refresh token: #{e.message}")
end
```

### Automatic Token Refresh

You can implement automatic token refresh by adding a method to your OauthIdentity model:

```ruby
# app/models/oauth_identity.rb
class OauthIdentity < ApplicationRecord
  belongs_to :user
  
  def ensure_fresh_token
    return token unless token_expired?
    return nil unless refresh_token.present?
    
    provider = Clavis.provider(provider.to_sym, redirect_uri: callback_url)
    
    begin
      new_tokens = provider.refresh_token(refresh_token)
      
      update(
        token: new_tokens[:access_token],
        refresh_token: new_tokens[:refresh_token] || refresh_token,
        expires_at: Time.at(new_tokens[:expires_at])
      )
      
      token
    rescue Clavis::TokenError => e
      Rails.logger.error("Failed to refresh token: #{e.message}")
      nil
    end
  end
  
  def token_expired?
    expires_at.present? && expires_at < Time.now
  end
  
  private
  
  def callback_url
    # Implement based on your application's routes
    Rails.application.routes.url_helpers.auth_callback_url(provider: provider, host: ENV['APP_HOST'])
  end
end
```

Then use it in your application:

```ruby
# Get a fresh token
fresh_token = user.oauth_identity_for(:google).ensure_fresh_token

# Use the token to make API calls
if fresh_token
  # Make API calls with the token
else
  # Handle the case where token refresh failed
end
```

### Error Handling for Token Refresh

When refreshing tokens, handle these common errors:

```ruby
begin
  new_tokens = provider.refresh_token(oauth_identity.refresh_token)
  # Update tokens...
rescue Clavis::InvalidGrant => e
  # The refresh token is invalid or expired
  # Force re-authentication
  redirect_to auth_path(provider: oauth_identity.provider)
rescue Clavis::TokenError => e
  # Other token-related errors
  Rails.logger.error("Token refresh error: #{e.message}")
  # Handle based on your application's needs
rescue Clavis::ProviderAPIError => e
  # Provider API errors
  Rails.logger.error("Provider API error: #{e.message}")
  # Handle based on your application's needs
end
```

### Best Practices for Token Refresh

1. **Store Refresh Tokens Securely**: Refresh tokens are long-lived credentials that should be stored securely.

2. **Handle Token Expiration Proactively**: Check token expiration before making API calls and refresh if needed.

3. **Implement Retry Logic**: If a token refresh fails due to network issues, implement retry logic with backoff.

4. **Monitor Refresh Failures**: Log and monitor token refresh failures to detect issues early.

5. **Graceful Degradation**: If token refresh fails, provide a graceful user experience, such as prompting for re-authentication.

6. **Refresh Before Expiration**: Refresh tokens before they expire to ensure uninterrupted service.

7. **Revoke Unused Tokens**: When a user logs out or unlinks an OAuth provider, revoke their refresh tokens.

## Custom Providers

Clavis supports custom OAuth providers through two approaches:

1. Using the built-in Generic provider with configuration
2. Creating your own provider class by extending the Base provider

### Using the Generic Provider

The Generic provider allows you to configure any OAuth 2.0 provider by specifying the necessary endpoints:

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  config.providers = {
    # ... other providers
    
    # Custom provider using the Generic provider
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
end
```

Then use it like any other provider:

```ruby
# In your controller
redirect_to auth_url(:custom_provider)

# In your view
<%= oauth_button :custom_provider, text: "Sign in with Custom Provider" %>
```

### Creating a Custom Provider Class

For more control, you can create your own provider class by extending `Clavis::Providers::Base`:

```ruby
# app/lib/my_app/providers/example_oauth.rb
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
# config/initializers/clavis.rb
require_relative '../../app/lib/my_app/providers/example_oauth'

Clavis.register_provider(:example_oauth, MyApp::Providers::ExampleOAuth)

Clavis.configure do |config|
  config.providers = {
    # ... other providers
    
    # Configuration for your custom provider
    example_oauth: {
      client_id: ENV['EXAMPLE_OAUTH_CLIENT_ID'],
      client_secret: ENV['EXAMPLE_OAUTH_CLIENT_SECRET'],
      redirect_uri: 'https://your-app.com/auth/example_oauth/callback'
    }
  }
end
```

Then use it like any other provider:

```ruby
# In your controller
redirect_to auth_url(:example_oauth)

# In your view
<%= oauth_button :example_oauth, text: "Sign in with Example" %>
```

## Provider-Specific Setup

### Google

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Select "Web application" as the application type
6. Add your application's domain to "Authorized JavaScript origins"
7. Add your callback URL to "Authorized redirect URIs" (e.g., `https://your-app.com/auth/google/callback`)
8. Copy the Client ID and Client Secret to your Clavis configuration

For token refresh, Google requires the `access_type=offline` parameter during the initial authorization:

```ruby
# This is already handled by Clavis for Google provider
def authorize_url(state:, nonce:, scope: nil)
  params = {
    # ... other params
    access_type: "offline",
    prompt: "consent"  # Force consent screen to ensure refresh token
  }
  # ...
end
```

### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in your application details
4. Set the "Authorization callback URL" to your callback URL (e.g., `https://your-app.com/auth/github/callback`)
5. Click "Register application"
6. Copy the Client ID and generate a Client Secret
7. Add these to your Clavis configuration

GitHub's refresh token implementation follows the standard OAuth 2.0 specification.

### Apple

1. Go to the [Apple Developer Portal](https://developer.apple.com/)
2. Navigate to "Certificates, Identifiers & Profiles"
3. Create a new "Services ID" identifier
4. Enable "Sign In with Apple" for this identifier
5. Configure your domains and redirect URLs
6. Create a private key for "Sign In with Apple"
7. Configure Clavis with your Services ID, Team ID, Key ID, and private key:

```ruby
config.providers = {
  apple: {
    client_id: ENV['APPLE_CLIENT_ID'], # Your Services ID
    team_id: ENV['APPLE_TEAM_ID'],
    key_id: ENV['APPLE_KEY_ID'],
    private_key: ENV['APPLE_PRIVATE_KEY'],
    redirect_uri: 'https://your-app.com/auth/apple/callback'
  }
}
```

Note: Apple doesn't provide refresh tokens. You'll need to re-authenticate the user when their token expires.

### Facebook

1. Go to [Facebook for Developers](https://developers.facebook.com/)
2. Create a new app or select an existing one
3. Add the "Facebook Login" product
4. Configure the "Valid OAuth Redirect URIs" with your callback URL
5. Copy the App ID and App Secret to your Clavis configuration

Facebook doesn't use standard refresh tokens but provides long-lived tokens through a custom exchange process, which Clavis handles automatically.

### Microsoft

1. Go to the [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" > "App registrations"
3. Create a new registration
4. Add a redirect URI of type "Web" with your callback URL
5. Under "Certificates & secrets", create a new client secret
6. Copy the Application (client) ID and the client secret to your Clavis configuration

Microsoft Azure AD follows the standard OAuth 2.0 refresh token flow.

## Testing Your Integration

After setting up Clavis, test the integration:

1. Visit your sign-in page
2. Click on one of the OAuth provider buttons
3. Authenticate with the provider
4. You should be redirected back to your application and signed in

## Troubleshooting

If you encounter issues:

1. Check your Rails logs for detailed error messages
2. Verify that your client IDs and secrets are correct
3. Ensure your redirect URIs match exactly what's configured with the provider
4. Check that your callback routes are correctly defined
5. Verify that your database migrations have been run

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/clayton/clavis. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/clayton/clavis/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Clavis project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/clayton/clavis/blob/main/CODE_OF_CONDUCT.md).
