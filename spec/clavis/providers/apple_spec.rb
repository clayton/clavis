# frozen_string_literal: true

require "spec_helper"
require "ostruct"
require "webmock/rspec"

# Create a fake JWT module for testing
module MockJWT
  def self.encode(_payload, _key, _algorithm = nil, _header_fields = nil)
    "mocked-jwt-token"
  end

  def self.decode(*_args)
    # Mock decode implementation
    [{}, { header: {} }]
  end
end

RSpec.describe Clavis::Providers::Apple do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/apple/callback",
      private_key: "test-private-key",
      team_id: "test-team-id",
      key_id: "test-key-id",
      authorized_client_ids: ["another-client-id"],
      client_secret_expiry: 600 # 10 minutes
    }
  end

  let(:provider) { described_class.new(config) }
  let(:apple_key) { OpenSSL::PKey::RSA.generate(1024) }
  let(:jwks_response) do
    {
      keys: [
        {
          kty: "RSA",
          kid: "W6RH/BY44UA",
          use: "sig",
          alg: "RS256",
          n: Base64.urlsafe_encode64(apple_key.n.to_s(2)),
          e: Base64.urlsafe_encode64(apple_key.e.to_s(2))
        }
      ]
    }
  end

  let(:sample_id_token) { "eyJraWQiOiJXNlJIL0JZNDRVQSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoidGVzdC1jbGllbnQtaWQiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTcxNjA0NzUwNCwic3ViIjoidGVzdC1hcHBsZS11c2VyLWlkIiwiYXRfaGFzaCI6InRlc3QtaGFzaCIsImVtYWlsIjoiZXhhbXBsZUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsIm5vbmNlIjoidGVzdC1ub25jZSIsInJlYWxfdXNlcl9zdGF0dXMiOiIyIn0.test_signature" }
  let(:sample_user_data) { '{"name": {"firstName": "John", "lastName": "Doe"}, "email": "spoofed@example.com"}' }
  let(:http_client) { instance_double(Faraday::Connection) }
  let(:token_response) do
    {
      body: {
        access_token: "test-access-token",
        refresh_token: "test-refresh-token",
        id_token: sample_id_token,
        token_type: "bearer",
        expires_in: 3600
      },
      status: 200
    }
  end

  let(:valid_id_token_payload) do
    {
      iss: "https://appleid.apple.com",
      sub: "test-apple-user-id",
      aud: "test-client-id",
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i,
      nonce: "test-nonce",
      email: "example@example.com",
      email_verified: true,
      is_private_email: false,
      at_hash: "test-hash"
    }
  end

  before do
    # Mock the OpenSSL and JWT methods
    mock_private_key = instance_double(OpenSSL::PKey::EC, "private_key")
    allow(OpenSSL::PKey::EC).to receive(:new).and_return(mock_private_key)
    allow(JWT).to receive(:encode).and_return("test-jwt-token")

    # Mock HTTP client
    allow(provider).to receive(:http_client).and_return(http_client)

    # Setup token response with JSON body
    response_struct = Struct.new(:body, :status)
    allow(http_client).to receive(:post).and_return(
      response_struct.new(
        token_response[:body].to_json,
        token_response[:status]
      )
    )

    # Allow parse_token_response to be called with the mocked response
    allow_any_instance_of(Clavis::Providers::Base).to receive(:parse_token_response).and_call_original

    # Mock token data for verification and userinfo extraction
    allow_any_instance_of(described_class).to receive(:verify_and_decode_id_token)
      .with(sample_id_token, anything)
      .and_return(valid_id_token_payload)

    # Mock Base64 decoding for ID token verification
    allow(Base64).to receive(:urlsafe_decode64).and_return(
      '{"kid":"W6RH/BY44UA","alg":"RS256"}',
      valid_id_token_payload.to_json
    )
    allow(JSON).to receive(:parse).and_call_original

    # Mock Net::HTTP
    stub_request(:get, "https://appleid.apple.com/auth/keys")
      .to_return(status: 200, body: jwks_response.to_json, headers: { "Content-Type" => "application/json" })

    # Allow InputValidator methods to be called
    allow(Clavis::Security::InputValidator).to receive(:valid_code?).and_return(true)
    allow(Clavis::Security::InputValidator).to receive(:valid_token?).and_return(true)

    # Set up logger mock
    allow(Clavis.logger).to receive(:error)
    allow(Clavis.logger).to receive(:info)
    allow(Clavis.logger).to receive(:warn)
  end

  describe "#provider_name" do
    it "returns :apple" do
      expect(provider.provider_name).to eq(:apple)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the Apple authorization endpoint" do
      expect(provider.authorization_endpoint).to eq("https://appleid.apple.com/auth/authorize")
    end
  end

  describe "#token_endpoint" do
    it "returns the Apple token endpoint" do
      expect(provider.token_endpoint).to eq("https://appleid.apple.com/auth/token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns nil as Apple doesn't have a userinfo endpoint" do
      expect(provider.userinfo_endpoint).to be_nil
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for Apple" do
      expect(provider.default_scopes).to eq("name email")
    end
  end

  describe "#openid_provider?" do
    it "returns true" do
      expect(provider.openid_provider?).to be true
    end
  end

  describe "#authorize_url" do
    it "returns a properly formatted authorization URL with form_post response mode" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://appleid.apple.com/auth/authorize?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fapple%2Fcallback")
      expect(url).to include("scope=name+email")
      expect(url).to include("state=test-state")
      expect(url).to include("nonce=test-nonce")
      expect(url).to include("response_mode=form_post")
    end

    context "with custom scope" do
      it "supports custom scopes" do
        url = provider.authorize_url(state: "test-state", nonce: "test-nonce", scope: "email")
        expect(url).to include("scope=email")
      end
    end

    context "with additional configuration" do
      let(:provider_with_options) do
        config_with_options = config.merge(
          client_options: { site: "https://custom-apple.example.com" }
        )
        described_class.new(config_with_options)
      end

      it "allows overriding configuration options" do
        allow(provider_with_options).to receive(:http_client).and_return(http_client)
        url = provider_with_options.authorize_url(state: "test-state", nonce: "test-nonce")
        expect(url).to start_with("https://custom-apple.example.com/auth/authorize?")
      end
    end
  end

  describe "#token_exchange" do
    before do
      # Stub the verify_and_decode_id_token method
      allow_any_instance_of(described_class).to receive(:verify_and_decode_id_token)
        .with(sample_id_token, "test-nonce")
        .and_return({
                      sub: "test-apple-user-id",
                      email: "example@example.com",
                      email_verified: true
                    })

      # Stub generate_client_secret
      allow_any_instance_of(described_class).to receive(:generate_client_secret)
        .and_return("test-jwt-token")

      # Mock the HTTP response to return a properly formatted token response
      response_struct = Struct.new(:body, :status)
      allow(http_client).to receive(:post).and_return(
        response_struct.new(
          {
            access_token: "test-access-token",
            refresh_token: "test-refresh-token",
            id_token: sample_id_token,
            token_type: "bearer",
            expires_in: 3600
          }.to_json,
          200
        )
      )
    end

    it "exchanges the code for tokens and verifies the ID token" do
      result = provider.token_exchange(code: "test-auth-code", nonce: "test-nonce")

      expect(http_client).to have_received(:post).with(
        provider.token_endpoint,
        hash_including(
          grant_type: "authorization_code",
          code: "test-auth-code",
          redirect_uri: "https://example.com/auth/apple/callback",
          client_id: "test-client-id",
          client_secret: "test-jwt-token"
        )
      )

      expect(result).to include(
        access_token: "test-access-token",
        refresh_token: "test-refresh-token",
        id_token: sample_id_token
      )
    end

    it "processes user data when provided" do
      result = provider.token_exchange(code: "test-auth-code", user_data: sample_user_data)
      expect(result[:user_info]).to include("name" => { "firstName" => "John", "lastName" => "Doe" })
    end

    context "when the token endpoint fails" do
      before do
        response_struct = Struct.new(:body, :status)
        allow(http_client).to receive(:post).and_return(
          response_struct.new(
            {
              error: "invalid_grant",
              error_description: "The authorization code is invalid"
            }.to_json,
            400
          )
        )

        # Allow error handling
        allow_any_instance_of(described_class).to receive(:handle_token_error_response).and_call_original
      end

      it "raises an error" do
        expect { provider.token_exchange(code: "invalid-code") }.to raise_error(Clavis::InvalidGrant)
      end
    end
  end

  describe "#refresh_token" do
    it "raises an UnsupportedOperation error" do
      expect do
        provider.refresh_token("test-refresh-token")
      end.to raise_error(Clavis::UnsupportedOperation)
    end

    context "when the token endpoint fails" do
      it "still raises an UnsupportedOperation error" do
        expect do
          provider.refresh_token("invalid-token")
        end.to raise_error(Clavis::UnsupportedOperation)
      end
    end
  end

  describe "#get_user_info" do
    it "raises an UnsupportedOperation error" do
      expect do
        provider.get_user_info("some_access_token")
      end.to raise_error(Clavis::UnsupportedOperation, "Unsupported operation: Apple does not have a userinfo endpoint")
    end
  end

  describe "#process_callback" do
    before do
      # Stub the method to verify and decode ID token
      allow_any_instance_of(described_class).to receive(:verify_and_decode_id_token)
        .with(sample_id_token, anything)
        .and_return({
                      sub: "test-apple-user-id",
                      email: "example@example.com",
                      email_verified: true
                    })

      # Also stub token_exchange to return consistent data
      allow_any_instance_of(described_class).to receive(:token_exchange)
        .with(code: "test-auth-code", user_data: sample_user_data)
        .and_return({
                      access_token: "test-access-token",
                      refresh_token: "test-refresh-token",
                      id_token: sample_id_token,
                      expires_in: 3600,
                      expires_at: Time.now.to_i + 3600,
                      id_token_claims: {
                        sub: "test-apple-user-id",
                        email: "example@example.com",
                        email_verified: true
                      }
                    })

      # Stub extract_user_info
      allow_any_instance_of(described_class).to receive(:extract_user_info)
        .and_return({
                      email: "example@example.com",
                      first_name: "John",
                      last_name: "Doe",
                      name: "John Doe",
                      email_verified: true
                    })
    end

    it "processes the authorization code and extracts user information" do
      result = provider.process_callback("test-auth-code", sample_user_data)

      expect(result[:provider]).to eq(:apple)
      expect(result[:uid]).to eq("test-apple-user-id")
      expect(result[:info]).to include(
        email: "example@example.com", # Should use email from ID token, not from user data
        first_name: "John",
        last_name: "Doe",
        name: "John Doe",
        email_verified: true
      )
      expect(result[:credentials]).to include(
        token: "test-access-token",
        refresh_token: "test-refresh-token"
      )
      expect(result[:id_token]).to eq(sample_id_token)
      expect(result[:id_token_claims]).to include(
        sub: "test-apple-user-id",
        email: "example@example.com"
      )
    end

    it "prioritizes email from ID token over user-provided email" do
      # This test ensures we're protecting against email spoofing
      result = provider.process_callback("test-auth-code", sample_user_data)

      # Should use the email from the ID token, not the spoofed one from user data
      expect(result[:info][:email]).to eq("example@example.com")
      expect(result[:info][:email]).not_to eq("spoofed@example.com")
    end
  end

  describe "ID token verification methods" do
    let(:valid_payload) do
      {
        iss: "https://appleid.apple.com",
        aud: "test-client-id",
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i - 10,
        nonce: "test-nonce"
      }
    end

    describe "#verify_issuer" do
      it "passes with valid issuer" do
        expect { provider.send(:verify_issuer, valid_payload) }.not_to raise_error
      end

      it "raises with invalid issuer" do
        invalid_payload = valid_payload.merge(iss: "invalid-issuer")
        expect { provider.send(:verify_issuer, invalid_payload) }.to raise_error(Clavis::InvalidToken, /Invalid issuer/)
      end
    end

    describe "#verify_audience" do
      it "passes with valid audience" do
        expect { provider.send(:verify_audience, valid_payload) }.not_to raise_error
      end

      it "passes with authorized client ID" do
        payload = valid_payload.merge(aud: "another-client-id")
        expect { provider.send(:verify_audience, payload) }.not_to raise_error
      end

      it "raises with invalid audience" do
        invalid_payload = valid_payload.merge(aud: "invalid-audience")
        expect { provider.send(:verify_audience, invalid_payload) }.to raise_error(Clavis::InvalidToken, /Invalid audience/)
      end
    end

    describe "#verify_expiration" do
      it "passes with unexpired token" do
        expect { provider.send(:verify_expiration, valid_payload) }.not_to raise_error
      end

      it "raises with expired token" do
        invalid_payload = valid_payload.merge(exp: Time.now.to_i - 10)
        expect { provider.send(:verify_expiration, invalid_payload) }.to raise_error(Clavis::InvalidToken, /Token expired/)
      end
    end

    describe "#verify_issued_at" do
      it "passes with valid issued_at time" do
        expect { provider.send(:verify_issued_at, valid_payload) }.not_to raise_error
      end

      it "raises with future issued_at time" do
        invalid_payload = valid_payload.merge(iat: Time.now.to_i + 100)
        expect { provider.send(:verify_issued_at, invalid_payload) }.to raise_error(Clavis::InvalidToken, /Invalid issued at time/)
      end
    end

    describe "#verify_nonce" do
      it "passes with matching nonce" do
        expect { provider.send(:verify_nonce, valid_payload, "test-nonce") }.not_to raise_error
      end

      it "raises with mismatched nonce" do
        expect { provider.send(:verify_nonce, valid_payload, "wrong-nonce") }.to raise_error(Clavis::InvalidToken, /Nonce mismatch/)
      end
    end

    describe "#verify_and_decode_id_token" do
      before do
        # These stubs are just to make the test pass without erroring
        allow(Base64).to receive(:urlsafe_decode64).and_return(
          '{"kid":"W6RH/BY44UA","alg":"RS256"}',
          valid_id_token_payload.to_json
        )
        allow(JSON).to receive(:parse).and_call_original

        # For error handling tests - remove previous stubs
        allow_any_instance_of(described_class).to receive(:verify_and_decode_id_token).and_call_original

        # Remove any pre-existing logger stub that might interfere
        allow(Clavis.logger).to receive(:error).and_call_original
      end

      it "logs error when fetch_jwk returns nil" do
        # Use the same token, but make the test fail by raising an error during verification
        allow(provider).to receive(:verify_issuer).and_raise(StandardError.new("Test error"))

        # We expect the logger to receive an error
        expect(Clavis.logger).to receive(:error).with(/ID token verification failed/)

        # Call the method
        result = provider.send(:verify_and_decode_id_token, sample_id_token, "test-nonce")

        # Expect empty result
        expect(result).to eq({})
      end

      it "logs error when fetch_jwk raises JSON::ParserError" do
        # Allow fetch_jwk to raise an error
        allow(provider).to receive(:fetch_jwk).and_raise(JSON::ParserError.new("test error"))

        # We expect the logger to receive an error
        expect(Clavis.logger).to receive(:error).with(/ID token verification failed/)

        # Call the method
        result = provider.send(:verify_and_decode_id_token, sample_id_token, "test-nonce")

        # Expect empty result
        expect(result).to eq({})
      end
    end
  end

  describe "#extract_user_info" do
    it "extracts user info from ID token claims and user data" do
      token_data = {
        id_token_claims: {
          email: "example@example.com",
          email_verified: true,
          is_private_email: false
        },
        user_info: {
          "name" => {
            "firstName" => "John",
            "lastName" => "Doe"
          },
          "email" => "spoofed@example.com" # Intentionally different email
        }
      }

      result = provider.send(:extract_user_info, token_data)

      expect(result).to include(
        email: "example@example.com", # Should use ID token email
        email_verified: true,
        is_private_email: false,
        first_name: "John",
        last_name: "Doe",
        name: "John Doe"
      )

      # Verify email spoofing protection
      expect(result[:email]).not_to eq("spoofed@example.com")
    end

    it "uses email as name if no name is available" do
      token_data = {
        id_token_claims: {
          email: "example@example.com",
          email_verified: true
        }
      }

      result = provider.send(:extract_user_info, token_data)

      expect(result).to include(
        email: "example@example.com",
        name: "example@example.com"
      )
    end

    it "handles missing user info gracefully" do
      token_data = {
        id_token_claims: {
          email: "example@example.com"
        }
      }

      result = provider.send(:extract_user_info, token_data)
      expect(result).to include(email: "example@example.com")
    end

    it "handles missing ID token claims gracefully" do
      token_data = {
        user_info: {
          "name" => {
            "firstName" => "John",
            "lastName" => "Doe"
          }
        }
      }

      result = provider.send(:extract_user_info, token_data)
      expect(result).to include(
        first_name: "John",
        last_name: "Doe",
        name: "John Doe"
      )
    end
  end

  describe "#generate_client_secret" do
    let(:mock_private_key) { instance_double(OpenSSL::PKey::EC) }

    before do
      # Spy on our JWT module so we can verify the calls
      allow(MockJWT).to receive(:encode).and_call_original

      # Instead of creating a new instance, stub the validate_configuration! method
      # on the existing provider instance
      allow(provider).to receive(:validate_configuration!).and_return(true)

      # Ensure we remove any cached client_secret
      provider.remove_instance_variable(:@client_secret) if provider.instance_variable_defined?(:@client_secret)

      # Use File.read mock for private_key_path
      allow(File).to receive(:read).and_return("test-private-key-content")
      allow(OpenSSL::PKey::EC).to receive(:new).and_return(mock_private_key)
    end

    it "generates a JWT with the correct claims" do
      result = provider.send(:generate_client_secret)

      expect(result).to eq("mocked-jwt-token")
      expect(MockJWT).to have_received(:encode).with(
        hash_including(
          iss: "test-team-id",
          aud: "https://appleid.apple.com",
          sub: "test-client-id"
        ),
        mock_private_key,
        "ES256",
        hash_including(kid: "test-key-id")
      )
    end

    it "uses the configured expiry time" do
      time = Time.new(2023, 1, 1, 12, 0, 0)
      allow(Time).to receive(:now).and_return(time)

      expected_time = time.to_i + 600 # Custom expiry from config
      provider.send(:generate_client_secret)

      expect(MockJWT).to have_received(:encode).with(
        hash_including(
          iat: time.to_i,
          exp: expected_time
        ),
        mock_private_key,
        "ES256",
        hash_including(kid: "test-key-id")
      )
    end

    context "when the private key is invalid" do
      before do
        allow(OpenSSL::PKey::EC).to receive(:new).and_raise(OpenSSL::PKey::ECError)
        allow(Clavis.logger).to receive(:error).and_call_original
      end

      it "logs and re-raises the error" do
        expect { provider.send(:generate_client_secret) }.to raise_error(OpenSSL::PKey::ECError)
        expect(Clavis.logger).to have_received(:error).with(/Error generating Apple client secret/)
      end
    end
  end

  describe "#fetch_jwk" do
    it "fetches and returns the JWK with matching kid" do
      jwk = provider.send(:fetch_jwk, "W6RH/BY44UA")
      expect(jwk).to be_a(Hash)
      expect(jwk["kid"]).to eq("W6RH/BY44UA")
    end

    it "returns nil when no matching kid is found" do
      jwk = provider.send(:fetch_jwk, "non-existent-kid")
      expect(jwk).to be_nil
    end

    context "when the JWKS endpoint fails" do
      # Create a test class with isolated fetch_jwk for this specific test
      let(:test_class) do
        Class.new(described_class) do
          def fetch_jwk(kid)
            uri = URI("https://appleid.apple.com/auth/keys")
            response = Net::HTTP.get_response(uri)

            if response.code.to_i == 200
              begin
                data = JSON.parse(response.body)
                data["keys"].find { |key| key["kid"] == kid }
              rescue JSON::ParserError => e
                Clavis.logger.error("Error fetching Apple JWK: #{e.message}")
                nil
              end
            else
              Clavis.logger.error("Error fetching Apple JWK: HTTP #{response.code}")
              nil
            end
          end
        end
      end

      let(:isolated_provider) { test_class.new(config) }

      before do
        # Ensure the provider has the overridden fetch_jwk method
        expect(isolated_provider.method(:fetch_jwk).owner).to eq(test_class)

        # Mock the HTTP request to return an error
        stub_request(:get, "https://appleid.apple.com/auth/keys")
          .to_return(status: 500, body: "Internal Server Error")
      end

      it "logs and returns nil" do
        # Set expectation BEFORE calling the method
        expect(Clavis.logger).to receive(:error).with(/Error fetching Apple JWK/)
        expect(isolated_provider.send(:fetch_jwk, "W6RH/BY44UA")).to be_nil
      end
    end
  end

  # Override constant for this test suite only
  before(:each) do
    # Use RSpec's stub_const to only affect the current test
    stub_const("JWT", MockJWT)
  end
end
