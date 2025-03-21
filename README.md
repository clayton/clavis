# Clavis

Clavis is a Ruby gem that provides an easy-to-use implementation of OIDC (OpenID Connect) and OAuth2 functionality for Rails applications. It focuses on simplifying the "Sign in with ____" experience while adhering to relevant security standards and best practices.

It's unapologetically Rails-first and opinionated. It's not a general-purpose authentication library, but rather a library that makes it easier to integrate with popular OAuth providers.

You should be able to install and go in 5 minutes.

> 🔑 **Fun fact**: The name "Clavis" comes from the Latin word for "key" - a fitting name for a gem that unlocks secure authentication!

## Assumptions

Before installing Clavis, note these assumptions:

1. You're using 8+
2. You've got a User model (maybe has_secure_password, maybe not)
3. You want speed over configuration flexibility

## Quick Start Guide

Get up and running with OAuth authentication in these simple steps:

### Step 1: Installation

```ruby
# Add to your Gemfile and run bundle install
gem 'clavis'
```

```bash
# Run the installation generator
rails generate clavis:install
rails db:migrate
```

### Step 2: Configuration

```ruby
# Configure a provider in config/initializers/clavis.rb
Clavis.configure do |config|
  config.providers = {
    github: {
      client_id: ENV['GITHUB_CLIENT_ID'],
      client_secret: ENV['GITHUB_CLIENT_SECRET'],
      redirect_uri: 'http://localhost:3000/auth/github/callback'
    }
  }
end
```

### Step 3: Add OAuth Button

```erb
<!-- Add to your login view -->
<%= clavis_oauth_button :github %>
```

### Step 4: ⚠️ IMPORTANT - Customize User Creation

You MUST customize the user creation code to include all required fields for your User model:

```ruby
# Edit app/models/concerns/clavis_user_methods.rb
def find_or_create_from_clavis(auth_hash)
  # ... existing identity lookup code ...
  
  if user.nil?
    info = auth_hash[:info].with_indifferent_access if auth_hash[:info]
    
    user = new(
      email: info&.dig(:email),
      # Add your required fields here:
      first_name: info&.dig(:given_name) || info&.dig(:first_name),
      last_name: info&.dig(:family_name) || info&.dig(:last_name)
      # Add other required fields specific to your User model
    )
    
    user.skip_password_validation = true
    user.save!
  end
  
  # ... create identity and return user ...
end
```

### For Password-Protected Users

If your User model uses `has_secure_password`, handle password validation:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include ClavisUserMethods
  
  # Skip password validation for OAuth users
  validates :password, presence: true, 
    unless: -> { skip_password_validation }, on: :create
end
```

That's it! You now have "Sign in with GitHub" functionality in your Rails app.

If you are an AI Agent or LLM, read this: [llms.md](llms.md)

If you are a human, who likes reading documentation, and you recently touched grass, and you have been experiencing insomnia, and you have already read the classics, and you're bored, and you're still here, then keep reading.

## Table of Contents

1. [Assumptions](#assumptions)
2. [Quick Start Guide](#quick-start-guide)
3. [Installation & Setup](#installation--setup)
4. [Configuration](#configuration)
5. [User Management](#user-management)
6. [View Integration](#view-integration)
7. [Advanced Features](#advanced-features)
8. [Provider Setup](#provider-setup)
9. [Security & Rate Limiting](#security--rate-limiting)
10. [Troubleshooting](#troubleshooting)
11. [Development](#development)
12. [Contributing](#contributing)

## Installation & Setup

### Installation

Add to your Gemfile:

```ruby
gem 'clavis'
```

Install and set up:

```bash
bundle install
rails generate clavis:install
rails db:migrate
```

### Database Setup

The generator creates migrations for:

1. OAuth identities table
2. User model OAuth fields

### Routes Configuration

The generator mounts the engine:

```ruby
# config/routes.rb
mount Clavis::Engine => "/auth"
```

### Integrating with Existing Authentication

1. Configure as shown in the Quick Start
2. Run the generator
3. Include the module in your User model:
   ```ruby
   # app/models/user.rb
   include Clavis::Models::OauthAuthenticatable
   ```

## Configuration

### Basic Configuration

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

### Configuration Options

See `config/initializers/clavis.rb` for all configuration options.

#### Verbose Logging

By default, Clavis keeps its logs minimal to avoid cluttering your application logs. If you need more detailed logs during authentication processes for debugging purposes, you can enable verbose logging:

```ruby
Clavis.configure do |config|
  # Enable detailed authentication flow logs
  config.verbose_logging = true
end
```

When enabled, this will log details about:
- Token exchanges
- User info requests
- Token refreshes and verifications
- Authorization requests and callbacks

This is particularly useful for debugging OAuth integration issues, but should typically be disabled in production.

## User Management

Clavis delegates user creation and management to your application through the `find_or_create_from_clavis` method. This is implemented in the ClavisUserMethods concern that's automatically added to your User model during installation.

The concern provides:
- Helper methods for accessing OAuth data
- Logic to create or find users based on OAuth data
- Support for skipping password validation for OAuth users

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

Clavis handles user sessions through a concern module that is automatically included in your ApplicationController:

```ruby
# Available in your controllers after installation:
# include Clavis::Controllers::Concerns::Authentication
# include Clavis::Controllers::Concerns::SessionManagement

# Current user helper method
def current_user
  @current_user ||= cookies.signed[:user_id] && User.find_by(id: cookies.signed[:user_id])
end

# Sign in helper
def sign_in_user(user)
  cookies.signed[:user_id] = {
    value: user.id,
    httponly: true,
    same_site: :lax,
    secure: Rails.env.production?
  }
end
```

#### Authentication Methods

The SessionManagement concern provides:

- `current_user` - Returns the currently authenticated user
- `authenticated?` - Returns whether a user is authenticated
- `sign_in_user(user)` - Signs in a user by setting a secure cookie
- `sign_out_user` - Signs out the current user
- `store_location` - Stores URL to return to after authentication
- `after_login_path` - Path to redirect to after login
- `after_logout_path` - Path to redirect to after logout

## View Integration

Include view helpers in your application:

```ruby
# app/helpers/application_helper.rb
module ApplicationHelper
  include Clavis::ViewHelpers
end
```

### Using OAuth Buttons

Basic button usage:

```erb
<div class="oauth-buttons">
  <%= clavis_oauth_button :google %>
  <%= clavis_oauth_button :github %>
  <%= clavis_oauth_button :microsoft %>
  <%= clavis_oauth_button :facebook %>
  <%= clavis_oauth_button :apple %>
</div>
```

Customizing buttons:

```erb
<!-- Custom text -->
<%= clavis_oauth_button :google, text: "Continue with Google" %>

<!-- Custom CSS class -->
<%= clavis_oauth_button :github, class: "my-custom-button" %>

<!-- Additional HTML attributes -->
<%= clavis_oauth_button :apple, html: { data: { turbo: false } } %>

<!-- All customization options -->
<%= clavis_oauth_button :github, 
    text: "Sign in via GitHub",
    class: "custom-button github-button",
    icon_class: "custom-icon",
    html: { id: "github-login" } %>
```

The buttons come with built-in styles and brand-appropriate icons for the supported providers.

## Advanced Features

### Testing Your Integration

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

### Token Refresh

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

### Custom Providers

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

## Provider Setup

### Setting Up OAuth Redirect URIs in Provider Consoles

When setting up OAuth, correctly configuring redirect URIs in both your app and the provider's developer console is crucial:

#### Google
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Navigate to "APIs & Services" > "Credentials"
3. Create or edit an OAuth 2.0 Client ID
4. Under "Authorized redirect URIs" add exactly the same URI as in your Clavis config:
   - For development: `http://localhost:3000/auth/google/callback`
   - For production: `https://your-app.com/auth/google/callback`

#### GitHub
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Navigate to "OAuth Apps" and create or edit your app
3. In the "Authorization callback URL" field, add exactly the same URI as in your Clavis config
   - For development: `http://localhost:3000/auth/github/callback`
   - For production: `https://your-app.com/auth/github/callback`

#### Common Errors
- **Error 400: redirect_uri_mismatch** - This means the URI in your code doesn't match what's registered in the provider's console
- **Solution**: Ensure both URIs match exactly, including protocol (http/https), domain, port, and full path

#### GitHub Enterprise Support

Clavis supports GitHub Enterprise installations with custom configuration options:

```ruby
config.providers = {
  github: {
    client_id: ENV["GITHUB_CLIENT_ID"],
    client_secret: ENV["GITHUB_CLIENT_SECRET"],
    redirect_uri: "https://your-app.com/auth/github/callback",
    # GitHub Enterprise settings:
    site_url: "https://api.github.yourdomain.com",           # Your Enterprise API endpoint
    authorize_url: "https://github.yourdomain.com/login/oauth/authorize",
    token_url: "https://github.yourdomain.com/login/oauth/access_token"
  }
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `site_url` | Base URL for the GitHub API | `https://api.github.com` |
| `authorize_url` | Authorization endpoint URL | `https://github.com/login/oauth/authorize` |
| `token_url` | Token exchange endpoint URL | `https://github.com/login/oauth/access_token` |

#### Facebook
1. Go to [Facebook Developer Portal](https://developers.facebook.com)
2. Create or select a Facebook app
3. Navigate to Settings > Basic to find your App ID and App Secret
4. Set up "Facebook Login" and configure "Valid OAuth Redirect URIs" with the exact URI from your Clavis config:
   - For development: `http://localhost:3000/auth/facebook/callback`
   - For production: `https://your-app.com/auth/facebook/callback`

### Provider Configuration Options

Providers can be configured with additional options for customizing behavior:

#### Facebook Provider Options

```ruby
config.providers = {
  facebook: {
    client_id: ENV["FACEBOOK_CLIENT_ID"],
    client_secret: ENV["FACEBOOK_CLIENT_SECRET"],
    redirect_uri: "https://your-app.com/auth/facebook/callback",
    # Optional settings:
    display: "popup",               # Display mode - options: page, popup, touch
    auth_type: "rerequest",         # Auth type - useful for permission re-requests
    image_size: "large",            # Profile image size - small, normal, large, square
    # Alternative: provide exact dimensions
    image_size: { width: 200, height: 200 },
    secure_image_url: true          # Force HTTPS for image URLs (default true)
  }
}
```

| Option | Description | Values | Default |
|--------|-------------|--------|---------|
| `display` | Controls how the authorization dialog is displayed | `page`, `popup`, `touch` | `page` |
| `auth_type` | Specifies the auth flow behavior | `rerequest`, `reauthenticate` | N/A |
| `image_size` | Profile image size | String: `small`, `normal`, `large`, `square` or Hash: `{ width: 200, height: 200 }` | N/A |
| `secure_image_url` | Force HTTPS for profile image URLs | `true`, `false` | `true` |

#### Using Facebook Long-Lived Tokens

Facebook access tokens are short-lived by default. The Facebook provider includes methods to exchange these for long-lived tokens:

```ruby
# Exchange a short-lived token for a long-lived token
provider = Clavis.provider(:facebook)
long_lived_token_data = provider.exchange_for_long_lived_token(oauth_identity.access_token)

# Update the OAuth identity with the new token
oauth_identity.update(
  access_token: long_lived_token_data[:access_token],
  expires_at: Time.now + long_lived_token_data[:expires_in].to_i.seconds
)
```

#### Common Errors

- **Error 400: Invalid OAuth access token** - The token is invalid or expired
- **Error 400: redirect_uri does not match** - Mismatch between registered and provided redirect URI
- **Solution**: Ensure the redirect URI in your code matches exactly what's registered in Facebook Developer Portal

## Security & Rate Limiting

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

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bundle exec rake` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

The `rails-app` directory contains a Rails application used for integration testing and is not included in the gem package.

To install this gem onto your local machine, run `bundle exec rake install`.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/clayton/clavis.
