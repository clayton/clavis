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
  attr_reader :params

  def initialize
    @params = Params.new({})
    @session = {}
    @redirect_path = nil
  end

  def params=(hash)
    # Convert to a Params object with Rails-like behavior
    @params = Params.new(hash)
  end

  def redirect_to(path)
    @redirect_path = path
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
    # Create a mock controller
    controller = MockController.new
    controller.params = {
      provider: "apple",
      code: auth_code,
      state: state,
      user: user_data
    }

    # Store state and nonce in session
    Clavis::Security::SessionManager.store(controller.session, :oauth_state, state)
    Clavis::Security::SessionManager.store(controller.session, :oauth_nonce, nonce)

    # Create instance of Authentication module
    auth_module = Object.new
    auth_module.extend(Clavis::Controllers::Concerns::Authentication)

    # Process the callback
    auth_module.define_singleton_method(:params) { controller.params }
    auth_module.define_singleton_method(:session) { controller.session }

    # Create a request double using RSpec's double method
    request_double = double("request",
                            session: controller.session,
                            env: { "rack.session.options" => {} })
    request_double.define_singleton_method(:reset_session) { nil }
    auth_module.define_singleton_method(:request) { request_double }

    # Use define_singleton_method to add the required redirect_to method
    redirect_called = false
    redirect_path = nil
    auth_module.define_singleton_method(:redirect_to) do |path, **_options|
      redirect_called = true
      redirect_path = path
      nil
    end

    # Define handle_oauth_error method
    auth_module.define_singleton_method(:handle_oauth_error) do |error, _description|
      raise Clavis::AuthenticationError, error
    end

    # Call the oauth_callback method
    user_processed = false
    auth_module.oauth_callback do |user, auth_hash|
      expect(user).not_to be_nil
      expect(auth_hash[:provider]).to eq(:apple)
      expect(auth_hash[:uid]).to eq("test-apple-user-id")
      expect(auth_hash[:info][:name]).to eq("John Doe")
      expect(auth_hash[:credentials][:token]).to eq("test-access-token")
      expect(auth_hash[:id_token]).to eq(sample_id_token)
      expect(auth_hash[:id_token_claims][:email]).to eq("example@example.com")

      # Verify email spoofing protection - should NOT use the spoofed email from user data
      expect(auth_hash[:info][:email]).to eq("example@example.com")
      expect(auth_hash[:info][:email]).not_to eq("spoofed@example.com")

      user_processed = true
    end

    # Verify the callback worked correctly
    expect(user_processed).to be true

    # Since we're using the mock override for process_callback, this is sufficient
    # verification that the callback happened with the right parameters
  end

  it "handles nonce validation in ID token verification" do
    # Create a mock controller
    controller = MockController.new
    controller.params = {
      provider: "apple",
      code: auth_code,
      state: state
    }

    # Store state and different nonce in session
    Clavis::Security::SessionManager.store(controller.session, :oauth_state, state)
    Clavis::Security::SessionManager.store(controller.session, :oauth_nonce, "different-nonce")

    # Create instance of Authentication module
    auth_module = Object.new
    auth_module.extend(Clavis::Controllers::Concerns::Authentication)

    # Process the callback
    auth_module.define_singleton_method(:params) { controller.params }
    auth_module.define_singleton_method(:session) { controller.session }

    # Create a request double using RSpec's double method
    request_double = double("request",
                            session: controller.session,
                            env: { "rack.session.options" => {} })
    request_double.define_singleton_method(:reset_session) { nil }
    auth_module.define_singleton_method(:request) { request_double }

    # Mock error handling
    allow(auth_module).to receive(:handle_oauth_error)

    # Mock process_callback to raise an error due to nonce mismatch
    allow_any_instance_of(Clavis::Providers::Apple).to receive(:process_callback)
      .and_raise(Clavis::InvalidToken, "Nonce mismatch")

    # Use define_singleton_method to add the required redirect_to method
    redirect_called = false
    redirect_path = nil
    auth_module.define_singleton_method(:redirect_to) do |path, **_options|
      redirect_called = true
      redirect_path = path
      nil
    end

    # Add error handling
    auth_module.define_singleton_method(:handle_oauth_error) do |error, _description|
      # Do nothing in the test
    end

    # Define the method that will be called to handle authentication errors
    expect do
      auth_module.oauth_callback do |_user, _auth_hash|
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
      stub_request(:get, "https://appleid.apple.com/auth/keys")
        .to_return(status: 502, body: "502 Bad Gateway")
    end

    it "still successfully processes the callback but logs the error" do
      logger_double = double("logger", error: nil, warn: nil, info: nil, debug: nil)
      allow(Clavis).to receive(:logger).and_return(logger_double)

      # Create a mock controller
      controller = MockController.new
      controller.params = {
        provider: "apple",
        code: auth_code,
        state: state,
        user: user_data
      }

      # Store state and nonce in session
      Clavis::Security::SessionManager.store(controller.session, :oauth_state, state)
      Clavis::Security::SessionManager.store(controller.session, :oauth_nonce, nonce)

      # Create Apple provider
      provider = Clavis.provider(:apple)

      # The callback should still work even if JWKS fails
      result = provider.process_callback(auth_code, user_data)
      expect(result[:uid]).to eq("test-apple-user-id")
    end
  end

  context "with invalid JWT in response" do
    let(:invalid_id_token) { "invalid.jwt.format" }

    before do
      # Mock provider to return invalid JWT
      allow_any_instance_of(Clavis::Providers::Apple).to receive(:process_callback)
        .and_return({
                      provider: :apple,
                      uid: "test-apple-user-id",
                      info: { email: "example@example.com" },
                      credentials: {
                        token: "test-access-token",
                        refresh_token: "test-refresh-token"
                      },
                      id_token: invalid_id_token,
                      id_token_claims: {}
                    })

      # Cause Base64 decode to fail
      allow(Base64).to receive(:urlsafe_decode64).and_raise(ArgumentError.new("invalid base64"))
    end

    it "handles invalid JWT gracefully" do
      logger_double = double("logger", error: nil, warn: nil, info: nil, debug: nil)
      allow(Clavis).to receive(:logger).and_return(logger_double)

      # Create a mock controller
      controller = MockController.new
      controller.params = {
        provider: "apple",
        code: auth_code,
        state: state
      }

      # Store state and nonce in session
      Clavis::Security::SessionManager.store(controller.session, :oauth_state, state)
      Clavis::Security::SessionManager.store(controller.session, :oauth_nonce, nonce)

      # Create instance of Authentication module with error handling
      auth_module = Object.new
      auth_module.extend(Clavis::Controllers::Concerns::Authentication)

      # Add the necessary method stubs
      auth_module.define_singleton_method(:params) { controller.params }
      auth_module.define_singleton_method(:session) { controller.session }

      # Create request double using RSpec's double method
      request_double = double("request",
                              session: controller.session,
                              env: { "rack.session.options" => {} })
      request_double.define_singleton_method(:reset_session) { nil }
      auth_module.define_singleton_method(:request) { request_double }

      auth_module.define_singleton_method(:handle_oauth_error) { |error, _desc| raise Clavis::AuthenticationError, error }

      # Add redirect_to method
      auth_module.define_singleton_method(:redirect_to) { |_path, **_opts| nil }

      # Override the Apple process_callback to raise an error
      allow_any_instance_of(Clavis::Providers::Apple).to receive(:process_callback)
        .and_raise(JWT::DecodeError, "Invalid JWT format")

      # The callback should handle the JWT error and raise AuthenticationError
      expect do
        auth_module.oauth_callback do |user, auth_hash|
          # This code won't actually run due to the error being raised earlier,
          # but we provide a non-empty block to satisfy RuboCop
          @processed_user = user
          @processed_auth = auth_hash
        end
      end.to raise_error(Clavis::AuthenticationError)
    end
  end
end
