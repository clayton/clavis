# Clavis - Testing Plan

## Testing Philosophy

The Clavis testing strategy follows these principles:

1. **Spec Compliance**: Ensure strict adherence to OAuth 2.0 and OIDC specifications
2. **Security First**: Prioritize testing of security-related components
3. **Comprehensive Coverage**: Test all flows and edge cases
4. **Test Isolation**: Unit tests should not depend on external services
5. **Integration Verification**: End-to-end tests should verify complete flows

## Test Types

### 1. Unit Tests

Unit tests will validate individual components in isolation:

- Provider implementations
- Token handling
- Configuration management
- Helper methods
- View components

### 2. Integration Tests

Integration tests will verify components working together:

- Complete authorization flows
- Rails engine integration
- Generator functionality

### 3. Security Tests

Dedicated security tests will verify:

- Token validation
- State parameter protection
- CSRF mitigation
- Proper error handling

## OAuth and OIDC Compliance Testing

### Mock Provider Infrastructure

Create a standardized mock provider infrastructure that simulates real OAuth/OIDC providers:

```ruby
# spec/support/mock_oauth_provider.rb
class MockOAuthProvider
  attr_reader :requests

  def initialize(options = {})
    @options = {
      issuer: "https://mock-provider.example.com",
      authorization_endpoint: "/authorize",
      token_endpoint: "/token",
      jwks_uri: "/jwks",
      userinfo_endpoint: "/userinfo"
    }.merge(options)
    
    @requests = []
    @tokens = {}
    @codes = {}
    @jwks = generate_jwks
  end
  
  def handle_request(method, path, params)
    @requests << { method: method, path: path, params: params }
    
    case path
    when @options[:authorization_endpoint]
      handle_authorization_request(params)
    when @options[:token_endpoint]
      handle_token_request(params)
    when @options[:userinfo_endpoint]
      handle_userinfo_request(params)
    when @options[:jwks_uri]
      handle_jwks_request(params)
    else
      [404, {}, ["Not Found"]]
    end
  end
  
  private
  
  def handle_authorization_request(params)
    # Validate client_id, redirect_uri, scope, etc.
    # Generate code and store with associated parameters
    # Return redirect to redirect_uri with code
  end
  
  def handle_token_request(params)
    # Validate code, client_id, client_secret, etc.
    # Generate tokens and return JSON response
  end
  
  # Additional handler methods...
end
```

### Authorization Flow Testing

Test the complete authorization code flow:

```ruby
# spec/integration/authorization_flow_spec.rb
RSpec.describe "Authorization Code Flow", type: :integration do
  let(:mock_provider) { MockOAuthProvider.new }
  
  before do
    # Configure provider in Clavis
    Clavis.configure do |config|
      config.providers = {
        mock: {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "http://localhost/auth/mock/callback"
        }
      }
    end
    
    # Configure Faraday to use the mock provider
    allow_any_instance_of(Faraday::Connection).to receive(:get) do |_, url, params|
      uri = URI(url)
      mock_provider.handle_request(:get, uri.path, params)
    end
    
    allow_any_instance_of(Faraday::Connection).to receive(:post) do |_, url, params|
      uri = URI(url)
      mock_provider.handle_request(:post, uri.path, params)
    end
  end
  
  it "successfully completes the authorization flow" do
    # 1. Initiate authorization
    auth_url = Clavis.provider(:mock).authorize_url(
      state: "test-state",
      nonce: "test-nonce",
      scope: "openid email profile"
    )
    
    # 2. Verify authorization URL parameters
    expect(auth_url).to include("response_type=code")
    expect(auth_url).to include("client_id=test-client-id")
    expect(auth_url).to include("redirect_uri=")
    expect(auth_url).to include("scope=openid+email+profile")
    expect(auth_url).to include("state=test-state")
    expect(auth_url).to include("nonce=test-nonce")
    
    # 3. Simulate authorization response
    callback_params = { code: "test-auth-code", state: "test-state" }
    
    # 4. Exchange code for tokens
    auth_response = Clavis.provider(:mock).token_exchange(
      code: callback_params[:code],
      expected_state: "test-state"
    )
    
    # 5. Verify token response
    expect(auth_response).to include(:access_token)
    expect(auth_response).to include(:id_token)
    expect(auth_response).to include(:token_type)
    expect(auth_response[:token_type]).to eq("Bearer")
    
    # 6. Verify ID token claims
    id_token = auth_response[:id_token]
    parsed_token = Clavis.provider(:mock).parse_id_token(id_token)
    
    expect(parsed_token["iss"]).to eq(mock_provider.options[:issuer])
    expect(parsed_token["sub"]).to be_present
    expect(parsed_token["aud"]).to eq("test-client-id")
    expect(parsed_token["nonce"]).to eq("test-nonce")
  end
end
```

### ID Token Validation Testing

Test proper validation of ID tokens according to OIDC spec:

```ruby
# spec/providers/base_spec.rb
RSpec.describe Clavis::Providers::Base do
  describe "#validate_id_token" do
    let(:mock_provider) { MockOAuthProvider.new }
    let(:valid_token_payload) do
      {
        iss: mock_provider.options[:issuer],
        sub: "test-subject",
        aud: "test-client-id",
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i,
        nonce: "test-nonce"
      }
    end
    
    it "accepts valid tokens" do
      token = JWT.encode(valid_token_payload, mock_provider.signing_key, 'RS256')
      expect {
        subject.validate_id_token(token, nonce: "test-nonce")
      }.not_to raise_error
    end
    
    it "rejects tokens with invalid signature" do
      # Test with wrong signing key
      token = JWT.encode(valid_token_payload, OpenSSL::PKey::RSA.new(2048), 'RS256')
      expect {
        subject.validate_id_token(token, nonce: "test-nonce")
      }.to raise_error(Clavis::InvalidToken)
    end
    
    it "rejects expired tokens" do
      expired_payload = valid_token_payload.merge(exp: Time.now.to_i - 3600)
      token = JWT.encode(expired_payload, mock_provider.signing_key, 'RS256')
      expect {
        subject.validate_id_token(token, nonce: "test-nonce")
      }.to raise_error(Clavis::InvalidToken)
    end
    
    it "rejects tokens with incorrect audience" do
      wrong_aud_payload = valid_token_payload.merge(aud: "wrong-client-id")
      token = JWT.encode(wrong_aud_payload, mock_provider.signing_key, 'RS256')
      expect {
        subject.validate_id_token(token, nonce: "test-nonce")
      }.to raise_error(Clavis::InvalidToken)
    end
    
    it "rejects tokens with incorrect nonce" do
      token = JWT.encode(valid_token_payload, mock_provider.signing_key, 'RS256')
      expect {
        subject.validate_id_token(token, nonce: "wrong-nonce")
      }.to raise_error(Clavis::InvalidToken)
    end
  end
end
```

### State Parameter Testing

Test proper handling of the state parameter for CSRF protection:

```ruby
# spec/controllers/concerns/authentication_spec.rb
RSpec.describe Clavis::Controllers::Concerns::Authentication do
  describe "#oauth_callback" do
    let(:mock_controller) do
      Class.new(ActionController::Base) do
        include Clavis::Controllers::Concerns::Authentication
      end.new
    end
    
    before do
      allow(mock_controller).to receive(:params).and_return({
        provider: "mock",
        code: "test-auth-code",
        state: "test-state"
      })
      
      allow(mock_controller).to receive(:session).and_return({})
    end
    
    it "rejects callbacks with mismatched state parameter" do
      mock_controller.session[:oauth_state] = "different-state"
      
      expect {
        mock_controller.oauth_callback
      }.to raise_error(Clavis::InvalidState)
    end
    
    it "rejects callbacks with missing state parameter" do
      # No state in session
      
      expect {
        mock_controller.oauth_callback
      }.to raise_error(Clavis::MissingState)
    end
    
    it "accepts callbacks with matching state parameter" do
      mock_controller.session[:oauth_state] = "test-state"
      
      # Mock the provider callback
      allow(Clavis).to receive_message_chain(:provider, :process_callback)
        .and_return({provider: "mock", uid: "123"})
      
      # Mock user creation
      allow(mock_controller).to receive(:find_or_create_user_from_oauth)
        .and_return(double("User"))
      
      expect {
        mock_controller.oauth_callback { |user, auth| }
      }.not_to raise_error
    end
  end
end
```

### Error Handling Tests

Test how the system handles various OAuth/OIDC error responses:

```ruby
# spec/integration/error_handling_spec.rb
RSpec.describe "OAuth Error Handling", type: :integration do
  describe "authorization errors" do
    it "handles access_denied errors" do
      # Simulate user cancellation
      params = { error: "access_denied", error_description: "User denied access" }
      
      # Handle in controller
      controller = ApplicationController.new
      controller.params = params
      
      expect {
        controller.oauth_callback
      }.to raise_error(Clavis::AuthorizationDenied)
    end
    
    it "handles invalid_request errors" do
      params = { error: "invalid_request", error_description: "Missing required parameter" }
      
      # Test handling
    end
    
    # Test other standard OAuth error codes
  end
  
  describe "token endpoint errors" do
    it "handles invalid_grant errors" do
      # Simulate provider response for expired code
      response = {
        error: "invalid_grant",
        error_description: "Authorization code has expired"
      }
      
      # Mock Faraday to return this error
      allow_any_instance_of(Faraday::Connection).to receive(:post)
        .and_return(double(status: 400, body: response.to_json))
      
      expect {
        Clavis.provider(:mock).token_exchange(code: "expired-code")
      }.to raise_error(Clavis::InvalidGrant)
    end
    
    # Test other token endpoint errors
  end
end
```

### Provider-Specific Tests

Create dedicated tests for each supported provider's unique behaviors:

```ruby
# spec/providers/google_spec.rb
RSpec.describe Clavis::Providers::Google do
  it "uses the correct endpoints" do
    provider = described_class.new(client_id: "test", client_secret: "test")
    
    expect(provider.authorization_endpoint).to eq("https://accounts.google.com/o/oauth2/v2/auth")
    expect(provider.token_endpoint).to eq("https://oauth2.googleapis.com/token")
    expect(provider.userinfo_endpoint).to eq("https://openidconnect.googleapis.com/v1/userinfo")
  end
  
  it "requests the correct scopes" do
    provider = described_class.new(client_id: "test", client_secret: "test")
    url = provider.authorize_url(state: "test", nonce: "test", scope: nil)
    
    # Google should default to these scopes
    expect(url).to include("scope=openid+email+profile")
  end
  
  # Add tests for Google-specific behavior or responses
end

# Similar tests for other providers
```

### UserInfo Endpoint Testing

Test the retrieval and processing of claims from the UserInfo endpoint:

```ruby
# spec/integration/userinfo_spec.rb
RSpec.describe "UserInfo Endpoint", type: :integration do
  let(:mock_provider) { MockOAuthProvider.new }
  
  before do
    # Setup mocks
  end
  
  it "retrieves user info with a valid access token" do
    # Mock userinfo response
    userinfo = {
      sub: "12345",
      name: "Test User",
      email: "test@example.com",
      email_verified: true
    }
    
    allow_any_instance_of(Faraday::Connection).to receive(:get)
      .with(mock_provider.options[:userinfo_endpoint], anything)
      .and_return(double(status: 200, body: userinfo.to_json))
    
    # Get user info
    provider = Clavis.provider(:mock)
    result = provider.get_user_info("valid-access-token")
    
    # Verify
    expect(result[:sub]).to eq("12345")
    expect(result[:email]).to eq("test@example.com")
    expect(result[:name]).to eq("Test User")
  end
  
  it "handles unauthorized access token" do
    allow_any_instance_of(Faraday::Connection).to receive(:get)
      .and_return(double(status: 401, body: { error: "invalid_token" }.to_json))
    
    expect {
      Clavis.provider(:mock).get_user_info("invalid-token")
    }.to raise_error(Clavis::InvalidAccessToken)
  end
end
```

### Testing Compliance with Specific OIDC Requirements

Test specific requirements from the OIDC spec:

```ruby
# spec/compliance/oidc_spec.rb
RSpec.describe "OIDC Compliance", type: :compliance do
  describe "ID Token requirements" do
    it "validates all required claims" do
      # Test that id_token validation checks all required claims
      # (iss, sub, aud, exp, iat)
    end
    
    it "validates optional claims when present" do
      # Test validation of optional claims like auth_time, nonce, etc.
    end
  end
  
  describe "Authorization Request requirements" do
    it "includes all required parameters" do
      # Test that auth requests include response_type, client_id, redirect_uri
    end
    
    it "supports all response_type values" do
      # Test support for "code" response_type
    end
  end
  
  # Add more spec compliance tests
end
```

## Test Data and Fixtures

### Sample JWT Tokens

Create fixtures with sample valid and invalid JWTs for testing:

```ruby
# spec/fixtures/tokens/valid_id_token.json
{
  "header": {
    "alg": "RS256",
    "kid": "test-key-id",
    "typ": "JWT"
  },
  "payload": {
    "iss": "https://accounts.example.com",
    "sub": "123456789",
    "aud": "client-id",
    "exp": 1699999999,
    "iat": 1600000000,
    "auth_time": 1600000000,
    "nonce": "test-nonce",
    "name": "Test User",
    "email": "test@example.com"
  },
  "signature": "..."
}
```

### Sample Provider Responses

Create fixtures with sample responses from various endpoints:

```ruby
# spec/fixtures/auth_responses/google_success.json
{
  "access_token": "ya29.a0AfH6SMBx-...",
  "expires_in": 3599,
  "refresh_token": "1//04DvKh...",
  "scope": "openid https://www.googleapis.com/auth/userinfo.profile",
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJSUzI1..."
}

# spec/fixtures/auth_responses/google_error.json
{
  "error": "invalid_grant",
  "error_description": "Invalid authorization code"
}
```

## Security Testing

### XSS Protection

Test that all user-provided data is properly escaped in views:

```ruby
# spec/view_helpers_spec.rb
RSpec.describe Clavis::ViewHelpers do
  describe "#clavis_oauth_button" do
    it "properly escapes button text" do
      # Test with potential XSS string
      result = helper.clavis_oauth_button(:google, text: "<script>alert('XSS')</script>")
      
      # Verify it's escaped
      expect(result).not_to include("<script>")
      expect(result).to include("&lt;script&gt;")
    end
  end
end
```

### CSRF Protection

Test CSRF protection mechanisms:

```ruby
# spec/security/csrf_spec.rb
RSpec.describe "CSRF Protection", type: :security do
  it "generates unique state parameters for each request" do
    states = []
    10.times do
      states << Clavis::Utils::SecureToken.generate_state
    end
    
    # Verify all states are unique
    expect(states.uniq.count).to eq(10)
    
    # Verify states are sufficiently random
    states.each do |state|
      expect(state.length).to be >= 32
    end
  end
  
  it "validates state parameter on callback" do
    # Similar to previous state parameter tests
  end
end
```

## Continuous Integration Testing

Set up GitHub Actions workflow to automate testing:

```yaml
# .github/workflows/test.yml
name: Tests

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        ruby-version: ['3.1', '3.2']
        rails-version: ['7.0', '8.0']

    steps:
    - uses: actions/checkout@v3
    - name: Set up Ruby
      uses: ruby/setup-ruby@v1
      with:
        ruby-version: ${{ matrix.ruby-version }}
        bundler-cache: true
    - name: Install dependencies
      run: |
        gem install bundler
        bundle install --jobs 4 --retry 3
    - name: Run tests
      run: bundle exec rake
```

## Coverage Tracking

Set up test coverage tracking:

```ruby
# spec/spec_helper.rb
require 'simplecov'
SimpleCov.start 'rails' do
  add_filter '/spec/'
  add_filter '/lib/generators/'
  
  add_group 'Providers', 'lib/clavis/providers'
  add_group 'Controllers', 'lib/clavis/controllers'
  add_group 'Models', 'lib/clavis/models'
  add_group 'Utils', 'lib/clavis/utils'
end
```

## Test Environment Setup

```ruby
# spec/spec_helper.rb
RSpec.configure do |config|
  # Setup mocks and stubs for HTTP requests
  config.before(:each) do
    # Setup Faraday stubbing
    allow(Faraday).to receive(:new).and_return(double('Faraday::Connection'))
  end
  
  # Load support files
  Dir[File.expand_path("support/**/*.rb", __dir__)].each { |f| require f }
  
  # Other RSpec configuration
end
```

## Testing Generators

```ruby
# spec/generators/install_generator_spec.rb
require 'generators/clavis/install_generator'

RSpec.describe Clavis::InstallGenerator, type: :generator do
  destination File.expand_path("../tmp", __dir__)
  
  before do
    prepare_destination
    # Setup fake Rails app structure
    FileUtils.mkdir_p "#{destination_root}/app/models"
    File.write "#{destination_root}/app/models/user.rb", "class User < ApplicationRecord\nend"
  end
  
  context "with default options" do
    before { run_generator }
    
    it "creates an initializer" do
      assert_file "config/initializers/clavis.rb"
    end
    
    it "creates a migration" do
      assert_migration "db/migrate/add_oauth_to_users.rb"
    end
  end
  
  context "with specific providers" do
    before { run_generator %w(--providers=google github) }
    
    it "configures specified providers in the initializer" do
      assert_file "config/initializers/clavis.rb" do |content|
        assert_match(/config\.providers = {/, content)
        assert_match(/google:/, content)
        assert_match(/github:/, content)
      end
    end
  end
end
```

## Rails Controller Testing

```ruby
# spec/controllers/auth_controller_spec.rb
RSpec.describe Clavis::AuthController, type: :controller do
  routes { Clavis::Engine.routes }
  
  describe "GET #authorize" do
    it "redirects to the provider authorization URL" do
      get :authorize, params: { provider: "google" }
      
      expect(response).to have_http_status(:redirect)
      expect(response.location).to start_with("https://accounts.google.com/o/oauth2/v2/auth")
    end
    
    it "stores the state in the session" do
      get :authorize, params: { provider: "google" }
      
      expect(session[:oauth_state]).not_to be_nil
    end
  end
  
  describe "GET #callback" do
    before do
      # Setup test data
    end
    
    it "exchanges the code for tokens" do
      # Test successful callback
    end
    
    it "handles error responses" do
      # Test error handling
    end
  end
end
``` 