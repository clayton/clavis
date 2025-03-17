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
  redirect_url = session.delete(:oauth_redirect_url) || root_path
  
  # Validate the redirect URL
  Clavis::Security::RedirectUriValidator.validate_uri!(redirect_url)
  
  # Redirect to the validated URL
  redirect_to redirect_url
end
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