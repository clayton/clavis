# frozen_string_literal: true

require "spec_helper"
require "ostruct"
require "webmock/rspec"

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
    allow(OpenSSL::PKey::EC).to receive(:new).and_return(double("private_key"))
    allow(JWT).to receive(:encode).and_return("test-jwt-token")

    # Mock HTTP client
    allow(provider).to receive(:http_client).and_return(http_client)
    allow(http_client).to receive(:post).and_return(OpenStruct.new(token_response))

    # Mock Base64 decoding for ID token verification
    allow(Base64).to receive(:urlsafe_decode64).and_return(
      '{"kid":"W6RH/BY44UA","alg":"RS256"}',
      valid_id_token_payload.to_json
    )
    allow(JSON).to receive(:parse).and_call_original

    # Mock Net::HTTP
    stub_request(:get, "https://appleid.apple.com/auth/keys")
      .to_return(status: 200, body: jwks_response.to_json, headers: { "Content-Type" => "application/json" })
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

  describe "#refresh_token" do
    it "exchanges a refresh token for a new access token" do
      result = provider.refresh_token("test-refresh-token")

      expect(http_client).to have_received(:post).with(
        provider.token_endpoint,
        hash_including(
          grant_type: "refresh_token",
          refresh_token: "test-refresh-token",
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

    context "when the token endpoint fails" do
      it "raises an error" do
        allow(http_client).to receive(:post).and_return(
          OpenStruct.new(
            body: { error: "invalid_grant", error_description: "The refresh token is invalid" },
            status: 400
          )
        )

        expect { provider.refresh_token("invalid-refresh-token") }
          .to raise_error(Clavis::InvalidGrant, /The refresh token is invalid/)
      end
    end
  end

  describe "#token_exchange" do
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

      # It should extract and verify ID token claims
      expect(result[:id_token_claims]).to include(
        iss: "https://appleid.apple.com",
        aud: "test-client-id",
        sub: "test-apple-user-id",
        email: "example@example.com"
      )
    end

    it "processes user data when provided" do
      result = provider.token_exchange(code: "test-auth-code", user_data: sample_user_data)

      expect(result[:user_info]).to include(
        "name" => { "firstName" => "John", "lastName" => "Doe" },
        "email" => "spoofed@example.com"
      )
    end

    context "when the token endpoint fails" do
      it "raises an error" do
        allow(http_client).to receive(:post).and_return(
          OpenStruct.new(
            body: { error: "invalid_grant", error_description: "The authorization code is invalid" },
            status: 400
          )
        )

        expect { provider.token_exchange(code: "invalid-code") }
          .to raise_error(Clavis::InvalidGrant, /The authorization code is invalid/)
      end
    end
  end

  describe "#get_user_info" do
    it "raises an UnsupportedOperation error" do
      expect do
        provider.get_user_info("some_access_token")
      end.to raise_error(Clavis::UnsupportedOperation, "Apple does not have a userinfo endpoint")
    end
  end

  describe "#process_callback" do
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

  describe "#verify_and_decode_id_token" do
    it "verifies and decodes a valid ID token" do
      result = provider.send(:verify_and_decode_id_token, sample_id_token, "test-nonce")

      expect(result).to include(
        iss: "https://appleid.apple.com",
        aud: "test-client-id",
        sub: "test-apple-user-id",
        email: "example@example.com",
        nonce: "test-nonce"
      )
    end

    # Tests for each type of invalid claim - using shared examples
    shared_examples :raises_invalid_token do |claim_name, error_pattern|
      it "raises an error for invalid #{claim_name}" do
        expect do
          provider.send(:verify_and_decode_id_token, sample_id_token, "test-nonce")
        end.to raise_error(Clavis::InvalidToken, error_pattern)
      end
    end

    context "with invalid issuer" do
      before do
        modified_payload = valid_id_token_payload.merge(iss: "https://invalid-issuer.com")
        allow(Base64).to receive(:urlsafe_decode64).and_return(
          '{"kid":"W6RH/BY44UA","alg":"RS256"}',
          modified_payload.to_json
        )
      end

      it_behaves_like :raises_invalid_token, :issuer, /Invalid issuer/
    end

    context "with invalid audience" do
      before do
        modified_payload = valid_id_token_payload.merge(aud: "invalid-client-id")
        allow(Base64).to receive(:urlsafe_decode64).and_return(
          '{"kid":"W6RH/BY44UA","alg":"RS256"}',
          modified_payload.to_json
        )
      end

      it_behaves_like :raises_invalid_token, :audience, /Invalid audience/
    end

    context "with expired token" do
      before do
        modified_payload = valid_id_token_payload.merge(exp: Time.now.to_i - 3600)
        allow(Base64).to receive(:urlsafe_decode64).and_return(
          '{"kid":"W6RH/BY44UA","alg":"RS256"}',
          modified_payload.to_json
        )
      end

      it_behaves_like :raises_invalid_token, :expiration, /Token expired/
    end

    context "with future issued-at time" do
      before do
        modified_payload = valid_id_token_payload.merge(iat: Time.now.to_i + 3600)
        allow(Base64).to receive(:urlsafe_decode64).and_return(
          '{"kid":"W6RH/BY44UA","alg":"RS256"}',
          modified_payload.to_json
        )
      end

      it_behaves_like :raises_invalid_token, :issued_at, /Invalid issued at time/
    end

    context "with nonce mismatch" do
      before do
        modified_payload = valid_id_token_payload.merge(nonce: "different-nonce")
        allow(Base64).to receive(:urlsafe_decode64).and_return(
          '{"kid":"W6RH/BY44UA","alg":"RS256"}',
          modified_payload.to_json
        )
      end

      it_behaves_like :raises_invalid_token, :nonce, /Nonce mismatch/
    end

    context "when JWKS fetching fails" do
      before do
        stub_request(:get, "https://appleid.apple.com/auth/keys")
          .to_return(status: 502, body: "502 Bad Gateway")
      end

      it "logs the error" do
        expect(Clavis.logger).to receive(:error).with(/Error fetching Apple JWK/)
        provider.send(:verify_and_decode_id_token, sample_id_token, "test-nonce")
      end
    end

    context "when JWKS response is invalid JSON" do
      before do
        stub_request(:get, "https://appleid.apple.com/auth/keys")
          .to_return(status: 200, body: "invalid JSON", headers: { "Content-Type" => "application/json" })
      end

      it "logs the error" do
        expect(Clavis.logger).to receive(:error).with(/Error fetching Apple JWK/)
        provider.send(:verify_and_decode_id_token, sample_id_token, "test-nonce")
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
    it "generates a JWT with the correct claims" do
      provider.send(:generate_client_secret)

      expect(JWT).to have_received(:encode).with(
        hash_including(
          iss: "test-team-id",
          aud: "https://appleid.apple.com",
          sub: "test-client-id",
          exp: instance_of(Integer)
        ),
        instance_of(Object),
        "ES256",
        hash_including(kid: "test-key-id")
      )
    end

    it "uses the configured expiry time" do
      time = Time.new(2023, 1, 1, 12, 0, 0)
      allow(Time).to receive(:now).and_return(time)

      provider.send(:generate_client_secret)

      expected_time = time.to_i + 600 # 10 minutes from config
      expect(JWT).to have_received(:encode).with(
        hash_including(
          iat: time.to_i,
          exp: expected_time
        ),
        instance_of(Object),
        "ES256",
        hash_including(kid: "test-key-id")
      )
    end

    context "when the private key is invalid" do
      before do
        allow(OpenSSL::PKey::EC).to receive(:new).and_raise(OpenSSL::PKey::ECError.new("Invalid key format"))
      end

      it "logs and re-raises the error" do
        expect(Clavis.logger).to receive(:error).with(/Error generating Apple client secret/)
        expect { provider.send(:generate_client_secret) }.to raise_error(OpenSSL::PKey::ECError)
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
      before do
        stub_request(:get, "https://appleid.apple.com/auth/keys")
          .to_return(status: 500, body: "Internal Server Error")
      end

      it "logs and returns nil" do
        expect(Clavis.logger).to receive(:error).with(/Error fetching Apple JWK/)
        expect(provider.send(:fetch_jwk, "W6RH/BY44UA")).to be_nil
      end
    end
  end
end
