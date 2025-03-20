# Security Best Practices for Clavis

This document outlines security best practices for using the Clavis gem in your Rails application.

## Configuration

### HTTPS Enforcement

Clavis enforces HTTPS for all OAuth URLs by default. This ensures that all communication with OAuth providers is encrypted.

```ruby
# In config/initializers/clavis.rb
Clavis.configure do |config|
  # Enable HTTPS enforcement (enabled by default)
  config.enforce_https = true
  
  # Allow HTTP for localhost in development (enabled by default)
  config.allow_http_localhost = true
  
  # Verify SSL certificates (enabled by default)
  config.verify_ssl = true
  
  # Set minimum TLS version (TLS 1.2 by default)
  config.minimum_tls_version = :TLS1_2
end
```

In production environments, HTTPS is always enforced, and SSL certificate validation is always enabled, regardless of configuration.

### Token Encryption

Clavis can encrypt OAuth tokens before storing them in your database. This adds an extra layer of protection for sensitive tokens.

```ruby
# In config/initializers/clavis.rb
Clavis.configure do |config|
  # Enable token encryption
  config.encrypt_tokens = true
  
  # Set encryption key (must be at least 32 bytes)
  config.encryption_key = ENV['CLAVIS_ENCRYPTION_KEY']
  
  # Use Rails credentials for encryption key
  config.use_rails_credentials = true
end
```

For Rails applications, you can store the encryption key in your credentials:

```yaml
# In config/credentials.yml.enc
clavis:
  encryption_key: your_secure_encryption_key_at_least_32_bytes_long
```

### Redirect URI Validation

Clavis validates redirect URIs to prevent open redirector vulnerabilities. You should configure allowed hosts for your application:

```ruby
# In config/initializers/clavis.rb
Clavis.configure do |config|
  # Set allowed redirect hosts
  config.allowed_redirect_hosts = ['your-app.com', 'www.your-app.com']
  
  # Enable exact matching for redirect URIs
  config.exact_redirect_uri_matching = true
  
  # Allow localhost in development
  config.allow_localhost_in_development = true
  
  # Raise an exception for invalid redirect URIs
  config.raise_on_invalid_redirect = true
end
```

### Parameter Filtering

Clavis filters sensitive parameters from logs by default. This prevents sensitive information like tokens and authorization codes from being logged.

```ruby
# In config/initializers/clavis.rb
Clavis.configure do |config|
  # Enable parameter filtering (enabled by default)
  config.parameter_filter_enabled = true
end
```

### Input Validation

Clavis validates and sanitizes all inputs by default. This helps prevent injection attacks and other security vulnerabilities.

```ruby
# In config/initializers/clavis.rb
Clavis.configure do |config|
  # Enable input validation (enabled by default)
  config.validate_inputs = true
  
  # Enable input sanitization (enabled by default)
  config.sanitize_inputs = true
end
```

### Session Management

Clavis includes secure session management features, including session rotation after authentication to prevent session fixation attacks.

```ruby
# In config/initializers/clavis.rb
Clavis.configure do |config|
  # Enable session rotation after login (enabled by default)
  config.rotate_session_after_login = true
  
  # Set prefix for session keys (default: 'clavis')
  config.session_key_prefix = 'clavis'
end
```

### Rate Limiting

Clavis integrates with Rack::Attack to provide rate limiting for OAuth endpoints, protecting against DDoS and brute force attacks.

```ruby
# In config/initializers/clavis.rb
Clavis.configure do |config|
  # Enable rate limiting (enabled by default)
  config.rate_limiting_enabled = true
  
  # Configure custom throttle rules
  config.custom_throttles = {
    "login_page": {
      limit: 30,
      period: 1.minute,
      block: ->(req) { req.path == "/login" ? req.ip : nil }
    }
  }
end
```

By default, Clavis applies the following rate limits:

- **OAuth Authorization Endpoints**: 20 requests per minute per IP address
- **OAuth Callback Endpoints**: 15 requests per minute per IP address
- **Login Attempts by Email**: 5 requests per 20 seconds per email address

For more advanced configuration, you can define custom Rack::Attack rules in a separate initializer:

```ruby
# config/initializers/rack_attack.rb
Rack::Attack.blocklist("block suspicious requests") do |req|
  # Block requests that contain SQL injection patterns
  req.path.include?("' OR '1'='1") || req.path.include?("--")
end

# Customize throttled response
Rack::Attack.throttled_responder = lambda do |req|
  [429, {'Content-Type' => 'application/json'}, [{ error: "Too many requests" }.to_json]]
end

# Use a dedicated Redis instance for rate limiting
Rack::Attack.cache.store = ActiveSupport::Cache::RedisCacheStore.new(
  url: ENV["REDIS_RATE_LIMIT_URL"]
)
```

## Model Security

### ActiveRecord Encryption

For Rails 7+ applications, you can use ActiveRecord Encryption to encrypt OAuth tokens in the database:

```ruby
# In app/models/oauth_identity.rb
class OauthIdentity < ApplicationRecord
  encrypts :token, :refresh_token, 
           deterministic: false, 
           downcase: false, 
           previous: []
end
```

### Token Storage

If you're not using ActiveRecord Encryption, you can use Clavis's token encryption:

```ruby
# In app/models/oauth_identity.rb
class OauthIdentity < ApplicationRecord
  # Override getters and setters to use Clavis's token encryption
  def token
    Clavis::Security::TokenStorage.decrypt(super)
  end
  
  def token=(value)
    super(Clavis::Security::TokenStorage.encrypt(value))
  end
  
  def refresh_token
    Clavis::Security::TokenStorage.decrypt(super)
  end
  
  def refresh_token=(value)
    super(Clavis::Security::TokenStorage.encrypt(value))
  end
end
```

## Controller Security

### Using the Authentication Controller Generator

Clavis provides a generator to create a secure authentication controller:

```bash
rails generate clavis:controller Auth
```

This will create:
- An `AuthController` with secure OAuth methods
- A login view with OAuth provider buttons
- Routes for OAuth authentication

You can customize the controller name:

```bash
rails generate clavis:controller Authentication
```

### CSRF Protection

Clavis includes built-in CSRF protection for OAuth flows. The state parameter is automatically generated and validated.

```ruby
# In your controller
def oauth_callback
  # State parameter is automatically validated
  auth_hash = oauth_provider.process_callback(params[:code])
  
  # Process the auth hash
  user = User.find_or_create_from_oauth(auth_hash)
  
  # Sign in the user
  sign_in(user)
  
  # Redirect to a safe URL
  redirect_to dashboard_path
end
```

### Secure Redirects

Always validate redirect URLs before redirecting:

```ruby
# In your controller
def oauth_callback
  # Process OAuth callback
  
  # Get the redirect URL from the session
  redirect_url = Clavis::Security::SessionManager.validate_and_retrieve_redirect_uri(
    session,
    default: root_path
  )
  
  # Redirect to the validated URL
  redirect_to redirect_url
end
```

### Session Rotation

Clavis automatically rotates the session ID after authentication to prevent session fixation attacks:

```ruby
# In your controller
def oauth_callback
  # Process OAuth callback
  
  # Rotate the session ID (done automatically by Clavis)
  # You can preserve specific keys during rotation
  Clavis::Security::SessionManager.rotate_session_id(
    session,
    SecureRandom.hex(32),
    preserve_keys: [:user_id, :return_to]
  )
  
  # Redirect to a safe URL
  redirect_to dashboard_path
end
```

## Input Validation and Sanitization

Clavis provides comprehensive input validation and sanitization:

```ruby
# Validate a URL
if Clavis::Security::InputValidator.valid_url?(params[:redirect_uri])
  # URL is valid
end

# Validate a token
if Clavis::Security::InputValidator.valid_token?(params[:token])
  # Token is valid
end

# Sanitize user input
safe_input = Clavis::Security::InputValidator.sanitize(params[:user_input])

# Sanitize a hash of user inputs
safe_params = Clavis::Security::InputValidator.sanitize_hash(params.to_unsafe_h)
```

## General Security Recommendations

1. **Keep Dependencies Updated**: Regularly update Clavis and other dependencies to get security fixes.

2. **Use Environment Variables**: Store sensitive configuration in environment variables or Rails credentials, not in code.

3. **Implement Rate Limiting**: Add rate limiting to OAuth endpoints to prevent brute force attacks.

4. **Monitor for Suspicious Activity**: Log and monitor OAuth authentication attempts for suspicious patterns.

5. **Implement Multi-Factor Authentication**: Consider adding MFA for sensitive operations.

6. **Regular Security Audits**: Regularly audit your OAuth implementation for security vulnerabilities.

7. **Secure Session Management**: Use secure, HTTP-only cookies for session management.

8. **Implement Proper Error Handling**: Don't expose sensitive information in error messages.

## Reporting Security Issues

If you discover a security issue in Clavis, please report it by email to [security@example.com](mailto:security@example.com). Do not disclose security bugs publicly until they have been handled by the security team.

## Additional Resources

- [OAuth 2.0 Security Best Practices](https://oauth.net/2/security-best-practices/)
- [OpenID Connect Security](https://openid.net/specs/openid-connect-core-1_0.html#Security)
- [Rails Security Guide](https://guides.rubyonrails.org/security.html) 