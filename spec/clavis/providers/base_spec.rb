# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::Providers::Base do
  let(:provider_class) do
    Class.new(described_class) do
      def authorization_endpoint
        "https://example.com/auth"
      end

      def token_endpoint
        "https://example.com/token"
      end

      def userinfo_endpoint
        "https://example.com/userinfo"
      end
    end
  end

  let(:provider) do
    provider_class.new(
      client_id: "test_client_id",
      client_secret: "test_client_secret",
      redirect_uri: "https://myapp.com/callback"
    )
  end

  describe "#refresh_token" do
    let(:refresh_token) { "test_refresh_token" }
    let(:response_body) do
      {
        access_token: "new_access_token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "new_refresh_token"
      }.to_json
    end

    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response) { instance_double(Faraday::Response, status: 200, body: response_body) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:post).and_return(response)
      allow(Clavis::Logging).to receive(:log_token_refresh)
    end

    it "sends a refresh token request to the token endpoint" do
      expected_params = {
        grant_type: "refresh_token",
        refresh_token: refresh_token,
        client_id: "test_client_id",
        client_secret: "test_client_secret"
      }

      provider.refresh_token(refresh_token)

      expect(http_client).to have_received(:post).with(
        "https://example.com/token",
        expected_params
      )
    end

    it "returns the parsed token response" do
      result = provider.refresh_token(refresh_token)

      expect(result).to include(
        access_token: "new_access_token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "new_refresh_token"
      )
    end

    it "logs a successful token refresh" do
      provider.refresh_token(refresh_token)

      expect(Clavis::Logging).to have_received(:log_token_refresh).with(
        provider.provider_name,
        true
      )
    end

    context "when the token refresh fails" do
      let(:response) { instance_double(Faraday::Response, status: 400, body: { error: "invalid_grant" }.to_json) }

      before do
        allow(provider).to receive(:handle_token_error_response).and_raise(Clavis::InvalidGrant)
      end

      it "logs a failed token refresh" do
        expect { provider.refresh_token(refresh_token) }.to raise_error(Clavis::InvalidGrant)

        expect(Clavis::Logging).to have_received(:log_token_refresh).with(
          provider.provider_name,
          false
        )
      end

      it "handles the error response" do
        expect { provider.refresh_token(refresh_token) }.to raise_error(Clavis::InvalidGrant)

        expect(provider).to have_received(:handle_token_error_response).with(response)
      end
    end
  end
end
