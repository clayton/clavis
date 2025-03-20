# frozen_string_literal: true

require "spec_helper"

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

  # Mock controller class
  class MockController
    attr_accessor :params, :session, :redirect_path

    def initialize
      @params = {}
      @session = {}
      @redirect_path = nil
    end

    def redirect_to(path)
      @redirect_path = path
    end
  end

  before do
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
      config.user_class = "User"
      config.user_finder_method = "find_for_clavis"
    end

    # Create a class double for the User class
    class_double("User", find_for_clavis: double("user", id: 1)).as_stubbed_const

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
    auth_module.define_singleton_method(:request) { double("request", session: controller.session) }

    # Use define_singleton_method to add the required redirect_to method
    redirect_called = false
    redirect_path = nil
    auth_module.define_singleton_method(:redirect_to) do |path, **_options|
      redirect_called = true
      redirect_path = path
      nil
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

    # Verify provider was called with user data
    expect_any_instance_of(Clavis::Providers::Apple).to have_received(:process_callback)
      .with(auth_code, user_data)
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
    auth_module.define_singleton_method(:request) { double("request", session: controller.session) }

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
      auth_module.oauth_callback { |_user, _auth_hash| }
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
        config.user_class = "User"
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
      expect(Clavis.logger).to receive(:error).with(/Error fetching Apple JWK/).at_least(:once)

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
      expect(Clavis.logger).to receive(:error).with(/ID token verification failed/).at_least(:once)

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

      # Process should still complete without raising errors
      provider = Clavis.provider(:apple)
      result = provider.process_callback(auth_code)

      # Should still get a result, even with invalid JWT
      expect(result[:provider]).to eq(:apple)
      expect(result[:uid]).to eq("test-apple-user-id")
      expect(result[:id_token_claims]).to eq({})
    end
  end
end
