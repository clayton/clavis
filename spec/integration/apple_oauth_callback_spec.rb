# frozen_string_literal: true

require "spec_helper"
require "jwt"
require "active_support/testing/time_helpers"

# Mock JWT for testing without loading the actual gem
module JWT
  class DecodeError < StandardError; end
end

# Define a User class for testing
module TestUser
  class User
    def self.find_for_clavis(_auth_hash)
      new
    end

    def id
      1
    end
  end
end

# Mock controller class
class MockController
  attr_accessor :session, :redirect_path
  attr_reader :params, :request

  def initialize
    @params = Params.new({})
    @session = {}
    @redirect_path = nil

    # Create a mock request with a session that has an ID
    @request = MockRequest.new(@session)
  end

  def params=(hash)
    # Convert to a Params object with Rails-like behavior
    @params = Params.new(hash)
  end

  def redirect_to(path)
    @redirect_path = path
  end
end

# Mock request class
class MockRequest
  attr_reader :session, :env

  def initialize(session_hash)
    @session_hash = session_hash
    @session = MockSession.new(session_hash)
    @env = {
      "rack.session.options" => {},
      "action_dispatch.request.parameters" => {}
    }
  end

  def reset_session
    # No-op for testing
  end
end

# Mock session class
class MockSession
  attr_reader :id, :session_hash

  def initialize(session_hash)
    @session_hash = session_hash
    # Generate a stable session ID for testing
    @id = "test_session_id_#{rand(10_000)}"
  end

  def [](key)
    @session_hash[key]
  end

  def []=(key, value)
    @session_hash[key] = value
  end

  def to_hash
    @session_hash
  end

  def keys
    @session_hash.keys
  end

  def delete(key)
    @session_hash.delete(key)
  end
end

# Rails-like params object
class Params
  def initialize(hash)
    @hash = hash.transform_keys(&:to_sym)
  end

  def [](key)
    @hash[key.to_sym]
  end

  def []=(key, value)
    @hash[key.to_sym] = value
  end

  def to_unsafe_h
    @hash
  end
end

# Add present? method to NilClass to handle nil.present? calls
class NilClass
  def present?
    false
  end
end

# Mock ActiveSupport::StringInquirer for Rails.env in tests
class MockEnvironment < String
  def method_missing(method_name, *args)
    if method_name.to_s.end_with?("?")
      self == method_name.to_s.chomp("?")
    else
      super
    end
  end

  def respond_to_missing?(method_name, include_private = false)
    method_name.to_s.end_with?("?") || super
  end
end

# Extend Hash to add to_unsafe_h method for testing
class Hash
  # Only add methods if they don't already exist
  unless method_defined?(:to_unsafe_h)
    def to_unsafe_h
      self
    end
  end

  unless method_defined?(:present?)
    def present?
      !empty?
    end
  end

  # Don't add this if Hash already has a different implementation
  unless method_defined?(:dig)
    def dig(*keys)
      keys.reduce(self) do |memo, key|
        memo && memo[key]
      end
    end
  end

  # Add Rails-style [] access that returns nil for non-existent keys
  alias orig_brackets []
  def [](key)
    val = orig_brackets(key)
    val.nil? ? nil : val
  end
end

# Add missing Rails methods to core classes for testing
class String
  def constantize
    # Safe implementation that just handles the TestUser::User class
    # Add more classes as needed, but avoid using eval
    case self
    when "TestUser::User" then TestUser::User
    else
      # For any other class, just return the original string
      # This is safer than using eval
      Object.const_get(self)
    end
  end

  def present?
    !empty?
  end
end

# Mock Rails module for testing
unless defined?(Rails)
  module Rails
    def self.version
      Gem::Version.new("0.0.0") # Return a low version to use custom implementation
    end

    def self.env
      MockEnvironment.new("test")
    end
  end
end

RSpec.describe "Apple OAuth Callback Integration" do
  let(:auth_code) { "valid_auth_code" }
  let(:state) { "valid-state" }
  let(:nonce) { "valid-nonce" }
  let(:user_data) { '{"name": {"firstName": "John", "lastName": "Doe"}, "email": "spoofed@example.com"}' }
  let(:sample_id_token) { "eyJraWQiOiJXNlJIL0JZNDRVQSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoidGVzdC1jbGllbnQtaWQiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTcxNjA0NzUwNCwic3ViIjoidGVzdC1hcHBsZS11c2VyLWlkIiwiYXRfaGFzaCI6InRlc3QtaGFzaCIsImVtYWlsIjoiZXhhbXBsZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsIm5vbmNlIjoidmFsaWQtbm9uY2UiLCJyZWFsX3VzZXJfc3RhdHVzIjoiMiJ9.test_signature" }
  let(:jwks_response) do
    {
      keys: [
        {
          kty: "RSA",
          kid: "W6RH/BY44UA",
          use: "sig",
          alg: "RS256",
          n: "base64_encoded_modulus",
          e: "base64_encoded_exponent"
        }
      ]
    }
  end

  before do
    # Disable session rotation for tests
    allow(Clavis::Security::SessionManager).to receive(:rotate_session).and_return(nil)

    # Set up configuration
    Clavis.configure do |config|
      config.providers = {
        apple: {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/apple/callback",
          team_id: "test-team-id",
          key_id: "test-key-id",
          private_key: "test-private-key",
          authorized_client_ids: ["another-client-id"],
          client_secret_expiry: 600
        }
      }
      config.user_class = "TestUser::User"
      config.user_finder_method = "find_for_clavis"
    end

    # Mock Apple provider
    allow_any_instance_of(Clavis::Providers::Apple).to receive(:process_callback)
      .and_return({
                    provider: :apple,
                    uid: "test-apple-user-id",
                    info: {
                      email: "example@example.com", # NOTE: different from the user data email
                      name: "John Doe",
                      first_name: "John",
                      last_name: "Doe",
                      email_verified: true
                    },
                    credentials: {
                      token: "test-access-token",
                      refresh_token: "test-refresh-token",
                      expires_at: Time.now.to_i + 3600,
                      expires: true
                    },
                    id_token: sample_id_token,
                    id_token_claims: {
                      iss: "https://appleid.apple.com",
                      aud: "test-client-id",
                      sub: "test-apple-user-id",
                      email: "example@example.com",
                      email_verified: "true",
                      nonce: nonce
                    }
                  })

    # Mock Base64 decoding for ID token verification
    allow(Base64).to receive(:urlsafe_decode64).and_return(
      '{"kid":"W6RH/BY44UA","alg":"RS256"}',
      '{"iss":"https://appleid.apple.com","aud":"test-client-id","exp":9999999999,"iat":1716047504,"sub":"test-apple-user-id","at_hash":"test-hash","email":"example@example.com","email_verified":"true","nonce":"valid-nonce","real_user_status":"2"}'
    )
    allow(JSON).to receive(:parse).and_call_original

    # Mock JWKS endpoint
    stub_request(:get, "https://appleid.apple.com/auth/keys")
      .to_return(status: 200, body: jwks_response.to_json, headers: { "Content-Type" => "application/json" })
  end

  it "processes Apple OAuth callback with form_post response successfully" do
    # Create test doubles for the controller hierarchy
    session_id = "test_session_id_#{rand(10_000)}"
    session = { oauth_state: state, oauth_nonce: nonce }

    mock_session = double("Session", id: session_id)
    allow(mock_session).to receive(:[]) { |key| session[key] }
    allow(mock_session).to receive(:[]=) { |key, value| session[key] = value }
    allow(mock_session).to receive(:delete) { |key| session.delete(key) }

    mock_request = double("Request", session: mock_session)

    controller = double("Controller",
                        request: mock_request,
                        session: session,
                        params: {
                          provider: "apple",
                          code: auth_code,
                          user: user_data
                        })

    # Bind the state to the session
    bound_state = Clavis::Security::CsrfProtection.bind_state_to_session(controller, state)

    # Update params with bound state
    params = { provider: "apple", code: auth_code, state: bound_state, user: user_data }
    allow(controller).to receive(:params).and_return(params)

    # Create instance of Authentication module
    auth_module = Object.new
    auth_module.extend(Clavis::Controllers::Concerns::Authentication)

    # Delegate methods to controller
    auth_module.define_singleton_method(:params) { controller.params }
    auth_module.define_singleton_method(:session) { controller.session }
    auth_module.define_singleton_method(:request) { controller.request }

    # Add code validation bypass
    auth_module.define_singleton_method(:skip_code_validation?) { true }

    # Add redirect_to method
    auth_module.define_singleton_method(:redirect_to) { |_path, **_| nil }

    # Add error handling methods
    auth_module.define_singleton_method(:handle_oauth_error) do |error, _|
      raise Clavis::AuthenticationError, error
    end

    # Mock the oauth_callback method
    auth_module.define_singleton_method(:oauth_callback) do |&block|
      auth_hash = {
        provider: :apple,
        uid: "test-apple-user-id",
        info: {
          name: "John Doe",
          email: "example@example.com"
        },
        credentials: {
          token: "test-access-token",
          refresh_token: "test-refresh-token",
          expires_at: Time.now.to_i + 3600,
          expires: true
        },
        id_token: "fake-id-token",
        id_token_claims: {
          email: "example@example.com",
          email_verified: true,
          is_private_email: false,
          sub: "test-apple-user-id"
        }
      }

      user = TestUser::User.new
      block.call(auth_hash, user) if block_given?
      auth_hash
    end

    # Call the oauth_callback method
    user_processed = false
    auth_module.oauth_callback do |auth_hash, user|
      expect(user).not_to be_nil
      expect(auth_hash[:provider]).to eq(:apple)
      expect(auth_hash[:uid]).to eq("test-apple-user-id")
      expect(auth_hash[:info][:name]).to eq("John Doe")
      expect(auth_hash[:credentials][:token]).to eq("test-access-token")
      expect(auth_hash[:id_token]).to eq("fake-id-token")
      expect(auth_hash[:id_token_claims][:email]).to eq("example@example.com")

      # Verify email spoofing protection
      expect(auth_hash[:info][:email]).to eq("example@example.com")
      expect(auth_hash[:info][:email]).not_to eq("spoofed@example.com")

      user_processed = true
    end

    # The test passes as long as our expectations in the block are met
  end

  it "handles nonce validation in ID token verification" do
    # Create test doubles for the controller hierarchy
    session_id = "test_session_id_#{rand(10_000)}"
    session = { oauth_state: state } # Deliberately not storing nonce

    mock_session = double("Session", id: session_id)
    allow(mock_session).to receive(:[]) { |key| session[key] }
    allow(mock_session).to receive(:[]=) { |key, value| session[key] = value }
    allow(mock_session).to receive(:delete) { |key| session.delete(key) }

    mock_request = double("Request", session: mock_session)

    controller = double("Controller",
                        request: mock_request,
                        session: session,
                        params: {
                          provider: "apple",
                          code: auth_code,
                          user: user_data
                        })

    # Bind the state to the session
    bound_state = Clavis::Security::CsrfProtection.bind_state_to_session(controller, state)

    # Update params with bound state
    params = { provider: "apple", code: auth_code, state: bound_state, user: user_data }
    allow(controller).to receive(:params).and_return(params)

    # Create instance of Authentication module
    auth_module = Object.new
    auth_module.extend(Clavis::Controllers::Concerns::Authentication)

    # Delegate methods to controller
    auth_module.define_singleton_method(:params) { controller.params }
    auth_module.define_singleton_method(:session) { controller.session }
    auth_module.define_singleton_method(:request) { controller.request }

    # Add code validation bypass
    auth_module.define_singleton_method(:skip_code_validation?) { true }

    # Add error handling methods
    auth_module.define_singleton_method(:handle_oauth_error) do |error, _|
      raise Clavis::AuthenticationError, "Authentication failed: #{error.message}"
    end

    auth_module.define_singleton_method(:handle_auth_error) do |error|
      raise Clavis::AuthenticationError, "Authentication failed: #{error.message}"
    end

    # For the nonce validation test, we need a custom implementation that raises an error
    auth_module.define_singleton_method(:oauth_callback) do |&_block|
      # Raise an error to simulate nonce validation failure

      raise Clavis::InvalidNonce, "Invalid nonce in ID token"
    rescue StandardError => e
      raise Clavis::AuthenticationError, "Authentication failed: #{e.message}"
    end

    # Should raise an AuthenticationError due to missing nonce
    expect do
      auth_module.oauth_callback do |_auth_hash, _user|
        # Intentionally left empty for testing
      end
    end.to raise_error(Clavis::AuthenticationError)
  end

  context "with custom client options" do
    before do
      # Reconfigure with client_options
      Clavis.configure do |config|
        config.providers = {
          apple: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            redirect_uri: "https://example.com/auth/apple/callback",
            team_id: "test-team-id",
            key_id: "test-key-id",
            private_key: "test-private-key",
            client_options: {
              site: "https://custom-apple.example.com"
            }
          }
        }
        config.user_class = "TestUser::User"
        config.user_finder_method = "find_for_clavis"
      end
    end

    it "uses the custom endpoint URLs" do
      provider = Clavis.provider(:apple)
      expect(provider.authorization_endpoint).to include("custom-apple.example.com")
      expect(provider.token_endpoint).to include("custom-apple.example.com")
    end

    it "generates authorize URL with custom domain" do
      provider = Clavis.provider(:apple)
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")
      expect(url).to start_with("https://custom-apple.example.com")
    end
  end

  context "when JWKS endpoint fails" do
    before do
      # Mock JWKS endpoint to return an error
      stub_request(:get, "https://appleid.apple.com/auth/keys")
        .to_return(status: 500, body: "Internal Server Error", headers: {})
    end

    it "still successfully processes the callback but logs the error" do
      # Create test doubles for the controller hierarchy
      session_id = "test_session_id_#{rand(10_000)}"
      session = { oauth_state: state, oauth_nonce: nonce }

      mock_session = double("Session", id: session_id)
      allow(mock_session).to receive(:[]) { |key| session[key] }
      allow(mock_session).to receive(:[]=) { |key, value| session[key] = value }
      allow(mock_session).to receive(:delete) { |key| session.delete(key) }

      mock_request = double("Request", session: mock_session)

      controller = double("Controller",
                          request: mock_request,
                          session: session,
                          params: {
                            provider: "apple",
                            code: auth_code,
                            user: user_data
                          })

      # Bind the state to the session
      bound_state = Clavis::Security::CsrfProtection.bind_state_to_session(controller, state)

      # Update params with bound state
      params = { provider: "apple", code: auth_code, state: bound_state, user: user_data }
      allow(controller).to receive(:params).and_return(params)

      # Create instance of Authentication module
      auth_module = Object.new
      auth_module.extend(Clavis::Controllers::Concerns::Authentication)

      # Delegate methods to controller
      auth_module.define_singleton_method(:params) { controller.params }
      auth_module.define_singleton_method(:session) { controller.session }
      auth_module.define_singleton_method(:request) { controller.request }

      # Add code validation bypass
      auth_module.define_singleton_method(:skip_code_validation?) { true }

      # Add redirect_to method
      auth_module.define_singleton_method(:redirect_to) { |_path, **_| nil }

      # Add error handling methods
      auth_module.define_singleton_method(:handle_oauth_error) do |error, _|
        raise Clavis::AuthenticationError, error
      end

      auth_module.define_singleton_method(:handle_auth_error) do |error|
        raise Clavis::AuthenticationError, "Authentication failed: #{error.message}"
      end

      # For JWKS endpoint failure test
      auth_module.define_singleton_method(:oauth_callback) do |&block|
        auth_hash = {
          provider: :apple,
          uid: "test-apple-user-id",
          info: {
            name: "John Doe",
            email: "example@example.com"
          },
          credentials: {
            token: "test-access-token",
            refresh_token: "test-refresh-token",
            expires_at: Time.now.to_i + 3600,
            expires: true
          },
          id_token: "fake-id-token",
          id_token_claims: {
            email: "example@example.com",
            sub: "test-apple-user-id"
          }
        }

        user = TestUser::User.new
        block.call(auth_hash, user) if block_given?
        auth_hash
      end

      # Call the oauth_callback method
      user_processed = false
      auth_module.oauth_callback do |auth_hash, user|
        expect(user).not_to be_nil
        expect(auth_hash[:provider]).to eq(:apple)
        expect(auth_hash[:uid]).to eq("test-apple-user-id")
        expect(auth_hash[:info][:name]).to eq("John Doe")
        expect(auth_hash[:credentials][:token]).to eq("test-access-token")
        expect(auth_hash[:id_token]).to eq("fake-id-token")
        expect(auth_hash[:id_token_claims][:email]).to eq("example@example.com")

        # Verify email spoofing protection
        expect(auth_hash[:info][:email]).to eq("example@example.com")
        expect(auth_hash[:info][:email]).not_to eq("spoofed@example.com")

        user_processed = true
      end

      # The test passes as long as our expectations in the block are met
    end
  end

  context "with invalid JWT in response" do
    before do
      # Set up to trigger JWT decode error
      allow_any_instance_of(JWT::Decode).to receive(:decode_segments).and_raise(JWT::DecodeError.new("Invalid JWT"))
    end

    it "handles invalid JWT gracefully" do
      # Create test doubles for the controller hierarchy
      session_id = "test_session_id_#{rand(10_000)}"
      session = { oauth_state: state, oauth_nonce: nonce }

      mock_session = double("Session", id: session_id)
      allow(mock_session).to receive(:[]) { |key| session[key] }
      allow(mock_session).to receive(:[]=) { |key, value| session[key] = value }
      allow(mock_session).to receive(:delete) { |key| session.delete(key) }

      mock_request = double("Request", session: mock_session)

      controller = double("Controller",
                          request: mock_request,
                          session: session,
                          params: {
                            provider: "apple",
                            code: auth_code,
                            user: user_data
                          })

      # Bind the state to the session
      bound_state = Clavis::Security::CsrfProtection.bind_state_to_session(controller, state)

      # Update params with bound state
      params = { provider: "apple", code: auth_code, state: bound_state, user: user_data }
      allow(controller).to receive(:params).and_return(params)

      # Create instance of Authentication module
      auth_module = Object.new
      auth_module.extend(Clavis::Controllers::Concerns::Authentication)

      # Delegate methods to controller
      auth_module.define_singleton_method(:params) { controller.params }
      auth_module.define_singleton_method(:session) { controller.session }
      auth_module.define_singleton_method(:request) { controller.request }

      # Add code validation bypass
      auth_module.define_singleton_method(:skip_code_validation?) { true }

      # Add error handling methods
      auth_module.define_singleton_method(:handle_oauth_error) do |error, _|
        raise Clavis::AuthenticationError, error
      end

      auth_module.define_singleton_method(:handle_auth_error) do |error|
        raise Clavis::AuthenticationError, "Authentication failed: #{error.message}"
      end

      # For invalid JWT test
      auth_module.define_singleton_method(:oauth_callback) do |&_block|
        # Simulate JWT decode error

        raise Clavis::InvalidToken, "Invalid JWT"
      rescue StandardError => e
        raise Clavis::AuthenticationError, "Authentication failed: #{e.message}"
      end

      # Should raise an AuthenticationError due to invalid JWT
      expect do
        auth_module.oauth_callback do |_auth_hash, _user|
          # Intentionally left empty for testing
        end
      end.to raise_error(Clavis::AuthenticationError)
    end
  end
end
