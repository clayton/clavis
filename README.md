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
9. [Session Management](#session-management)
10. [Integration with has_secure_password](#integration-with-has_secure_password)
11. [Token Refresh](#token-refresh)
12. [Custom Providers](#custom-providers)
13. [Provider-Specific Setup](#provider-specific-setup)
14. [Rate Limiting](#rate-limiting)
15. [Testing Your Integration](#testing-your-integration)
16. [Troubleshooting](#troubleshooting)
17. [Development](#development)
18. [Contributing](#contributing)
19. [License](#license)
20. [Code of Conduct](#code-of-conduct)

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

Clavis delegates user creation and management to your application through a finder method. After installing Clavis, you need to set up your User model to handle OAuth users:

```bash
# Generate the Clavis user methods concern
rails generate clavis:user_method
```

This generates:
1. A `ClavisUserMethods` concern in `app/models/concerns/clavis_user_methods.rb`
2. Adds `include ClavisUserMethods` to your User model

The concern provides:
- Integration with the `OauthAuthenticatable` module for helper methods
- A `find_or_create_from_clavis` class method that handles user creation/lookup
- Conditional validation for password requirements (commented by default)

### Customizing User Creation

The generated concern includes a method to find or create users from OAuth data. By default, it only sets the email field, which may not be sufficient for your User model:

```ruby
# In app/models/concerns/clavis_user_methods.rb
def find_or_create_from_clavis(auth_hash)
  # For OpenID Connect providers (like Google), we use the sub claim as the stable identifier
  # For other providers, we use the uid
  identity = if auth_hash[:id_token_claims]&.dig(:sub)
              Clavis::OauthIdentity.find_by(
                provider: auth_hash[:provider],
                uid: auth_hash[:id_token_claims][:sub]
              )
            else
              Clavis::OauthIdentity.find_by(
                provider: auth_hash[:provider],
                uid: auth_hash[:uid]
              )
            end
  return identity.user if identity&.user

  # Finding existing user logic...
  
  # Create new user if none exists
  if user.nil?
    # Convert hash data to HashWithIndifferentAccess for reliable key access
    info = auth_hash[:info].with_indifferent_access if auth_hash[:info]
    
    user = new(
      email: info&.dig(:email)
      # You MUST add other required fields for your User model here!
    )
    
    user.save!
  end
  
  # Create or update the OAuth identity...
end
```

### OpenID Connect Providers and Stable Identifiers

For OpenID Connect providers (like Google), Clavis uses the `sub` claim from the ID token as the stable identifier. This is important because:

1. The `sub` claim is guaranteed to be unique and stable for each user
2. Other fields like `uid` might change between logins
3. This follows the OpenID Connect specification

For non-OpenID Connect providers (like GitHub), Clavis continues to use the `uid` field as the identifier.

⚠️ **IMPORTANT**: You **MUST** customize this method to set all required fields for your User model!

We use `with_indifferent_access` to reliably access fields regardless of whether keys are strings or symbols. The auth_hash typically contains:

```ruby
# Access these fields with info.dig(:field_name) 
info = auth_hash[:info].with_indifferent_access

# Common fields available in info:
info[:email]           # User's email address
info[:name]            # User's full name
info[:given_name]      # First name (Google)
info[:first_name]      # First name (some providers)
info[:family_name]     # Last name (Google)
info[:last_name]       # Last name (some providers)
info[:nickname]        # Username or handle
info[:picture]         # Profile picture URL (Google)
info[:image]           # Profile picture URL (some providers)
```

Example of customized user creation:

```ruby
# Convert to HashWithIndifferentAccess for reliable key access
info = auth_hash[:info].with_indifferent_access if auth_hash[:info]

user = new(
  email: info&.dig(:email),
  first_name: info&.dig(:given_name) || info&.dig(:first_name),
  last_name: info&.dig(:family_name) || info&.dig(:last_name),
  username: info&.dig(:nickname) || "user_#{SecureRandom.hex(4)}",
  avatar_url: info&.dig(:picture) || info&.dig(:image),
  terms_accepted: true
)
```

### Helper Methods

The concern includes the `OauthAuthenticatable` module, which provides helper methods:

```ruby
# Available on any user instance
user.oauth_user?        # => true if the user has any OAuth identities
user.oauth_identity     # => the primary OAuth identity
user.oauth_avatar_url   # => the profile picture URL
user.oauth_name         # => the name from OAuth
user.oauth_email        # => the email from OAuth
user.oauth_token        # => the access token
```

### Handling Password Requirements

For password-protected User models, the concern includes a commented-out conditional validation:

```ruby
# Uncomment in app/models/concerns/clavis_user_methods.rb
validates :password, presence: true, unless: :oauth_user?
```

This allows you to:
1. Skip password requirements for OAuth users
2. Keep your regular password validations for non-OAuth users
3. Avoid storing useless random passwords in your database

### Using a Different Class or Method

You can configure Clavis to use a different class or method name:

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  # Use a different class
  config.user_class = "Account"
  
  # Use a different method name
  config.user_finder_method = :create_from_oauth
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

## Rate Limiting

Clavis includes built-in integration with the [Rack::Attack](https://github.com/rack/rack-attack) gem to protect your OAuth endpoints against DDoS and brute force attacks.

### Setting Up Rate Limiting

1. Rack::Attack is included as a dependency in Clavis, so you don't need to add it separately.

2. Rate limiting is enabled by default. To customize it, update your Clavis configuration:

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  # Enable or disable rate limiting (enabled by default)
  config.rate_limiting_enabled = true
  
  # Configure custom throttles (optional)
  config.custom_throttles = {
    "login_page": {
      limit: 30,
      period: 1.minute,
      block: ->(req) { req.path == "/login" ? req.ip : nil }
    }
  }
end
```

### Default Rate Limits

By default, Clavis sets these rate limits:

- **OAuth Authorization Endpoints (`/auth/:provider`)**: 20 requests per minute per IP
- **OAuth Callback Endpoints (`/auth/:provider/callback`)**: 15 requests per minute per IP
- **Login Attempts by Email**: 5 requests per 20 seconds per email address

### Customizing Rack::Attack Configuration

For more advanced customization, you can configure Rack::Attack directly in an initializer:

```ruby
# config/initializers/rack_attack.rb
Rack::Attack.throttle("custom/auth/limit", limit: 10, period: 30.seconds) do |req|
  req.ip if req.path.start_with?("/auth/")
end

# Customize the response for throttled requests
Rack::Attack.throttled_responder = lambda do |req|
  [
    429,
    { 'Content-Type' => 'application/json' },
    [{ error: "Too many requests. Please try again later." }.to_json]
  ]
end
```

### Monitoring and Logging

Rack::Attack uses ActiveSupport::Notifications, so you can subscribe to events:

```ruby
# config/initializers/rack_attack_logging.rb
ActiveSupport::Notifications.subscribe("throttle.rack_attack") do |name, start, finish, id, payload|
  req = payload[:request]
  
  # Log throttled requests
  if req.env["rack.attack.match_type"] == :throttle
    Rails.logger.warn "Rate limit exceeded for #{req.ip}: #{req.path}"
  end
end
```

## Testing Your Integration

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

## Usage

### Basic Setup

1. Install the gem
2. Run the installation generator:

```
rails generate clavis:install
```

3. Configure your OAuth providers in `config/initializers/clavis.rb`:

```ruby
Clavis.configure do |config|
  # Configure your OAuth providers
  config.provider :github, client_id: "your-client-id", client_secret: "your-client-secret"
  
  # Add other configurations as needed
end
```

4. Generate an authentication controller:

```
rails generate clavis:controller Auth
```

5. Add the routes to your application:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  get 'auth/:provider/callback', to: 'auth#callback'
  get 'auth/failure', to: 'auth#failure'
  get 'auth/:provider', to: 'auth#authorize', as: :auth
  # ...
end
```

### User Management

Clavis creates a concern module that you can include in your User model:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::Concerns::ClavisUserMethods
  
  # Your existing user model code
end
```

This provides your User model with the `find_or_create_from_clavis` method that manages user creation from OAuth data.

### Session Management

Clavis handles user sessions through a concern module that is automatically included in your ApplicationController:

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  # Clavis automatically includes:
  # include Clavis::Controllers::Concerns::Authentication
  # include Clavis::Controllers::Concerns::SessionManagement
  
  # Your existing controller code
end
```

#### Secure Cookie-Based Authentication

The SessionManagement concern uses a secure cookie-based approach that is compatible with Rails 8's authentication patterns:

- **Signed Cookies**: User IDs are stored in signed cookies with security settings like `httponly`, `same_site: :lax`, and `secure: true` (in production)
- **Security-First**: Cookies are configured with security best practices to protect against XSS, CSRF, and cookie theft
- **No Session Storage**: User authentication state is not stored in the session, avoiding session fixation attacks

#### Authentication Methods

The SessionManagement concern provides the following methods:

- `current_user` - Returns the currently authenticated user (if any)
- `authenticated?` - Returns whether a user is currently authenticated
- `sign_in_user(user)` - Signs in a user by setting a secure cookie
- `sign_out_user` - Signs out the current user by clearing cookies
- `store_location` - Stores the current URL to return to after authentication (uses session for this temporary data only)
- `after_login_path` - Returns the path to redirect to after successful login (stored location or root path)
- `after_logout_path` - Returns the path to redirect to after logout (login path or root path)

#### Compatibility with Existing Authentication

The system is designed to work with various authentication strategies:

1. **Devise**: If your application uses Devise, Clavis will automatically use Devise's `sign_in` and `sign_out` methods.

2. **Rails 8 Authentication**: Compatible with Rails 8's cookie-based authentication approach.

3. **Custom Cookie Usage**: If you're already using `cookies.signed[:user_id]`, Clavis will work with this approach.

#### Customizing Session Management

You can override any of these methods in your ApplicationController to customize the behavior:

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  # Override the default after_login_path
  def after_login_path
    dashboard_path  # Redirect to dashboard instead of root
  end
  
  # Override sign_in_user to add additional behavior
  def sign_in_user(user)
    super  # Call the original method
    log_user_sign_in(user)  # Add your custom behavior
  end
  
  # Use a different cookie name or format
  def sign_in_user(user)
    cookies.signed.permanent[:auth_token] = {
      value: user.generate_auth_token,
      httponly: true,
      same_site: :lax,
      secure: Rails.env.production?
    }
  end
  
  # Customize how users are found
  def find_user_by_cookie
    return nil unless cookies.signed[:auth_token]
    User.find_by_auth_token(cookies.signed[:auth_token])
  end
end
```

## Configuration

See `config/initializers/clavis.rb` for all configuration options.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/your-username/clavis.

### Integration with has_secure_password

If your User model uses `has_secure_password` for authentication, you'll need to handle password validation carefully when creating users from OAuth. The generated ClavisUserMethods concern provides several strategies for dealing with this:

#### Option 1: Skip Password Validation (Recommended)

This approach adds a temporary attribute to mark OAuth users and skip password validation for them:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include ClavisUserMethods
  has_secure_password

  # Skip password validation for OAuth users
  validates :password, presence: true, length: { minimum: 8 },
           unless: -> { skip_password_validation }, on: :create
end
```

The `skip_password_validation` attribute is set automatically in the OAuth flow.

#### Option 2: Set Random Password

Another approach is to set a random secure password for OAuth users:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include ClavisUserMethods
  has_secure_password

  # Set a random password for OAuth users
  before_validation :set_random_password, 
                   if: -> { skip_password_validation && respond_to?(:password=) }
  
  private
  
  def set_random_password
    self.password = SecureRandom.hex(16)
    self.password_confirmation = password if respond_to?(:password_confirmation=)
  end
end
```

#### Option 3: Bypass Validations (Use with Caution)

As a last resort, you can bypass validations entirely when creating OAuth users:

```ruby
# In app/models/concerns/clavis_user_methods.rb
def self.find_or_create_from_clavis(auth_hash)
  # ... existing code ...
  
  # Create a new user if none exists
  if user.nil?
    # ... set user attributes ...
    
    # Bypass validations
    user.save(validate: false)
  end
  
  # ... remainder of method ...
end
```

This approach isn't recommended as it might bypass important validations, but can be necessary in complex scenarios.

#### Database Setup

The Clavis generator automatically adds an `oauth_user` boolean field to your User model to help track which users were created through OAuth:

```ruby
# This is added automatically by the generator
add_column :users, :oauth_user, :boolean, default: false
```

This field is useful for conditional logic related to authentication methods.

### Session Management

```ruby
Clavis.configure do |config|
  config.session_key = :clavis_current_user_id
  config.user_finder_method = :find_or_create_from_clavis
end
```

### The OauthIdentity Model

Clavis stores OAuth credentials and user information in a polymorphic `OauthIdentity` model. This model has a `belongs_to :authenticatable, polymorphic: true` relationship, allowing it to be associated with any type of user model.

For convenience, the model also provides `user` and `user=` methods that are aliases for `authenticatable` and `authenticatable=`:

```ruby
# These are equivalent:
identity.user = current_user
identity.authenticatable = current_user
```

This allows you to use `identity.user` in your code even though the underlying database uses the `authenticatable` columns.

#### Key features of the OauthIdentity model:

- Secure token storage (tokens are automatically encrypted/decrypted)
- User information stored in the `auth_data` JSON column
- Automatic token refresh capabilities
- Unique index on `provider` and `uid` to prevent duplicate identities

### Webhook Providers
