# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Token Refresh Integration" do
  let(:google_provider) do
    Clavis::Providers::Google.new(
      client_id: "google-client-id",
      client_secret: "google-client-secret",
      redirect_uri: "https://example.com/auth/google/callback"
    )
  end

  let(:facebook_provider) do
    Clavis::Providers::Facebook.new(
      client_id: "facebook-client-id",
      client_secret: "facebook-client-secret",
      redirect_uri: "https://example.com/auth/facebook/callback"
    )
  end

  let(:apple_provider) do
    Clavis::Providers::Apple.new(
      client_id: "com.example.app",
      client_secret: "apple-client-secret",
      redirect_uri: "https://example.com/auth/apple/callback",
      team_id: "TEAM123456",
      key_id: "KEY123456",
      private_key: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG...=\n-----END PRIVATE KEY-----\n"
    )
  end

  describe "Google token refresh" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:refresh_token) { "google-refresh-token" }
    let(:response) do
      instance_double(
        Faraday::Response,
        status: 200,
        body: {
          access_token: "new-google-access-token",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "new-google-refresh-token"
        }.to_json
      )
    end

    before do
      allow(google_provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:post).and_return(response)
      allow(Clavis::Logging).to receive(:log_token_refresh)
    end

    it "refreshes the token successfully" do
      result = google_provider.refresh_token(refresh_token)

      expect(http_client).to have_received(:post).with(
        "https://oauth2.googleapis.com/token",
        {
          grant_type: "refresh_token",
          refresh_token: refresh_token,
          client_id: "google-client-id",
          client_secret: "google-client-secret"
        }
      )

      expect(result).to include(
        access_token: "new-google-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "new-google-refresh-token"
      )

      expect(Clavis::Logging).to have_received(:log_token_refresh).with(:google, true)
    end
  end

  describe "Facebook token refresh" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:access_token) { "facebook-access-token" }
    let(:response) do
      instance_double(
        Faraday::Response,
        status: 200,
        body: {
          access_token: "new-facebook-long-lived-token",
          token_type: "Bearer",
          expires_in: 5_184_000 # 60 days
        }.to_json
      )
    end

    before do
      allow(facebook_provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(response)
      allow(Clavis::Logging).to receive(:log_token_refresh)
    end

    it "exchanges for a long-lived token" do
      result = facebook_provider.refresh_token(access_token)

      expect(http_client).to have_received(:get).with(
        a_string_matching(%r{^https://graph\.facebook\.com/v\d+\.\d+/oauth/access_token\?})
      )

      expect(result).to include(
        access_token: "new-facebook-long-lived-token",
        token_type: "Bearer",
        expires_in: 5_184_000
      )

      expect(Clavis::Logging).to have_received(:log_token_refresh).with(:facebook, true)
    end
  end

  describe "Apple token refresh" do
    it "raises an UnsupportedOperation error" do
      expect do
        apple_provider.refresh_token("some-token")
      end.to raise_error(Clavis::UnsupportedOperation, "Unsupported operation: Apple does not support refresh tokens")
    end
  end

  describe "Error handling" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:error_response) do
      instance_double(
        Faraday::Response,
        status: 400,
        body: {
          error: "invalid_grant",
          error_description: "The refresh token is invalid or has expired"
        }.to_json
      )
    end

    before do
      allow(google_provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:post).and_return(error_response)
      allow(Clavis::Logging).to receive(:log_token_refresh)
    end

    it "handles invalid grant errors" do
      expect do
        google_provider.refresh_token("expired-token")
      end.to raise_error(Clavis::InvalidGrant, "The refresh token is invalid or has expired")

      expect(Clavis::Logging).to have_received(:log_token_refresh).with(:google, false)
    end
  end
end
