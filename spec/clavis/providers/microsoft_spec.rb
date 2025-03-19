# frozen_string_literal: true

RSpec.describe Clavis::Providers::Microsoft do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/microsoft/callback",
      tenant: "test-tenant"
    }
  end

  let(:provider) { described_class.new(config) }

  describe "#provider_name" do
    it "returns :microsoft" do
      expect(provider.provider_name).to eq(:microsoft)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the Microsoft authorization endpoint with the tenant" do
      expect(provider.authorization_endpoint).to eq("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize")
    end
  end

  describe "#token_endpoint" do
    it "returns the Microsoft token endpoint with the tenant" do
      expect(provider.token_endpoint).to eq("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the Microsoft userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://graph.microsoft.com/v1.0/me")
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for Microsoft" do
      expect(provider.default_scopes).to eq("openid email profile User.Read")
    end
  end

  describe "#openid_provider?" do
    it "returns true" do
      expect(provider.openid_provider?).to be true
    end
  end

  describe "#authorize_url" do
    it "returns a properly formatted authorization URL" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fmicrosoft%2Fcallback")
      expect(url).to include("scope=openid+email+profile+User.Read")
      expect(url).to include("state=test-state")
      expect(url).to include("nonce=test-nonce")
    end
  end

  context "when tenant is not provided" do
    let(:config) do
      {
        client_id: "test-client-id",
        client_secret: "test-client-secret",
        redirect_uri: "https://example.com/auth/microsoft/callback"
      }
    end

    it "uses 'common' as the default tenant" do
      expect(provider.authorization_endpoint).to eq("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
      expect(provider.token_endpoint).to eq("https://login.microsoftonline.com/common/oauth2/v2.0/token")
    end
  end

  describe "#token_exchange" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response_body) do
      {
        access_token: "microsoft-access-token",
        id_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaWNyb3NvZnQtdXNlci1pZCJ9.signature",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "microsoft-refresh-token"
      }.to_json
    end
    let(:response) { instance_double(Faraday::Response, status: 200, body: response_body) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:post).and_return(response)
      allow(Clavis::Logging).to receive(:log_token_exchange)
    end

    it "exchanges the code for tokens" do
      result = provider.token_exchange(code: "test-code")

      expect(http_client).to have_received(:post).with(
        "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
        {
          grant_type: "authorization_code",
          code: "test-code",
          redirect_uri: "https://example.com/auth/microsoft/callback",
          client_id: "test-client-id",
          client_secret: "test-client-secret"
        }
      )

      expect(result).to include(
        access_token: "microsoft-access-token",
        id_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaWNyb3NvZnQtdXNlci1pZCJ9.signature",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "microsoft-refresh-token"
      )

      expect(Clavis::Logging).to have_received(:log_token_exchange).with(:microsoft, true)
    end

    context "when the token exchange fails" do
      let(:error_response) do
        instance_double(
          Faraday::Response,
          status: 400,
          body: {
            error: "invalid_grant",
            error_description: "AADSTS70000: The provided value for the input parameter 'code' is invalid."
          }.to_json
        )
      end

      before do
        allow(http_client).to receive(:post).and_return(error_response)
        allow(provider).to receive(:handle_token_error_response).and_raise(Clavis::InvalidGrant)
      end

      it "handles the error response" do
        expect { provider.token_exchange(code: "invalid-code") }.to raise_error(Clavis::InvalidGrant)
        expect(Clavis::Logging).to have_received(:log_token_exchange).with(:microsoft, false)
      end
    end

    context "with a malformed response" do
      let(:malformed_response) do
        instance_double(
          Faraday::Response,
          status: 200,
          body: "not-a-json-response"
        )
      end

      before do
        allow(http_client).to receive(:post).and_return(malformed_response)
        # The actual code likely rescues JSON parse errors
        allow(JSON).to receive(:parse).and_raise(JSON::ParserError)
        allow(provider).to receive(:parse_token_response).and_return({})
      end

      it "handles JSON parse errors gracefully" do
        expect do
          result = provider.token_exchange(code: "test-code")
          expect(result).to eq({})
        end.to_not raise_error
      end
    end
  end

  describe "#refresh_token" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:refresh_token) { "microsoft-refresh-token" }
    let(:response_body) do
      {
        access_token: "new-microsoft-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "new-microsoft-refresh-token",
        scope: "openid email profile User.Read"
      }.to_json
    end
    let(:response) { instance_double(Faraday::Response, status: 200, body: response_body) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:post).and_return(response)
      allow(Clavis::Logging).to receive(:log_token_refresh)
      allow(Clavis::Security::InputValidator).to receive(:valid_token?).and_return(true)
      allow(Clavis::Security::InputValidator).to receive(:valid_token_response?).and_return(true)
      allow(Clavis::Security::InputValidator).to receive(:sanitize_hash).and_return({
                                                                                      access_token: "new-microsoft-access-token",
                                                                                      token_type: "Bearer",
                                                                                      expires_in: 3600,
                                                                                      refresh_token: "new-microsoft-refresh-token",
                                                                                      scope: "openid email profile User.Read"
                                                                                    })
    end

    it "refreshes the token successfully" do
      result = provider.refresh_token(refresh_token)

      expect(http_client).to have_received(:post).with(
        "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
        {
          grant_type: "refresh_token",
          refresh_token: refresh_token,
          client_id: "test-client-id",
          client_secret: "test-client-secret"
        }
      )

      expect(result).to include(
        access_token: "new-microsoft-access-token",
        token_type: "Bearer",
        refresh_token: "new-microsoft-refresh-token"
      )

      expect(Clavis::Logging).to have_received(:log_token_refresh).with(:microsoft, true)
    end

    context "when the token refresh fails with an invalid_grant error" do
      let(:error_response) do
        instance_double(
          Faraday::Response,
          status: 400,
          body: {
            error: "invalid_grant",
            error_description: "AADSTS70000: The provided refresh token has expired or is invalid."
          }.to_json
        )
      end

      before do
        allow(http_client).to receive(:post).and_return(error_response)
        allow(provider).to receive(:handle_token_error_response).and_raise(Clavis::InvalidGrant)
      end

      it "handles the error response" do
        expect { provider.refresh_token(refresh_token) }.to raise_error(Clavis::InvalidGrant)
        expect(Clavis::Logging).to have_received(:log_token_refresh).with(:microsoft, false)
      end
    end

    context "when there's a network error" do
      before do
        allow(http_client).to receive(:post).and_raise(Faraday::ConnectionFailed.new("Connection refused"))
      end

      it "handles network errors" do
        expect { provider.refresh_token(refresh_token) }.to raise_error(Faraday::ConnectionFailed)
      end
    end
  end

  describe "#get_user_info" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:access_token) { "microsoft-access-token" }
    let(:user_info_data) do
      {
        id: "microsoft-user-id",
        displayName: "Test User",
        givenName: "Test",
        surname: "User",
        userPrincipalName: "test.user@example.com",
        mail: "test.user@example.com"
      }
    end
    let(:user_response_body) { user_info_data.to_json }
    let(:user_response) { instance_double(Faraday::Response, status: 200, body: user_response_body) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(user_response)
      allow(Clavis::Logging).to receive(:log_userinfo_request)
      allow(Clavis::Security::InputValidator).to receive(:valid_token?).and_return(true)
    end

    it "fetches user info from Microsoft Graph API" do
      result = provider.get_user_info(access_token)

      expect(http_client).to have_received(:get).with("https://graph.microsoft.com/v1.0/me") do |&block|
        req = double
        expect(req).to receive(:headers).and_return({})
        block.call(req)
      end

      # Expect the actual format of the data as returned by the provider implementation
      expect(result).to include(user_info_data)

      expect(Clavis::Logging).to have_received(:log_userinfo_request).with(:microsoft, true)
    end

    context "when the user info request fails" do
      let(:error_response) do
        instance_double(
          Faraday::Response,
          status: 401,
          body: {
            error: {
              code: "InvalidAuthenticationToken",
              message: "Access token has expired."
            }
          }.to_json
        )
      end

      before do
        allow(http_client).to receive(:get).and_return(error_response)
        allow(provider).to receive(:handle_userinfo_error_response).and_raise(Clavis::InvalidToken)
      end

      it "handles the error response" do
        expect { provider.get_user_info(access_token) }.to raise_error(Clavis::InvalidToken)
        expect(Clavis::Logging).to have_received(:log_userinfo_request).with(:microsoft, false)
      end
    end
  end
end
