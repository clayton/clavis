# frozen_string_literal: true

RSpec.describe Clavis::Providers::Github do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/github/callback"
    }
  end

  let(:provider) { described_class.new(config) }

  describe "#provider_name" do
    it "returns :github" do
      expect(provider.provider_name).to eq(:github)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the GitHub authorization endpoint" do
      expect(provider.authorization_endpoint).to eq("https://github.com/login/oauth/authorize")
    end
  end

  describe "#token_endpoint" do
    it "returns the GitHub token endpoint" do
      expect(provider.token_endpoint).to eq("https://github.com/login/oauth/access_token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the GitHub userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://api.github.com/user")
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for GitHub" do
      expect(provider.default_scopes).to eq("user:email")
    end
  end

  describe "#authorize_url" do
    it "returns a properly formatted authorization URL" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://github.com/login/oauth/authorize?")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgithub%2Fcallback")
      expect(url).to include("scope=user%3Aemail")
      expect(url).to include("state=test-state")
    end
  end

  describe "#token_exchange" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response_body) do
      {
        access_token: "github-access-token",
        token_type: "bearer",
        scope: "user:email"
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
        "https://github.com/login/oauth/access_token",
        {
          grant_type: "authorization_code",
          code: "test-code",
          redirect_uri: "https://example.com/auth/github/callback",
          client_id: "test-client-id",
          client_secret: "test-client-secret"
        }
      )

      expect(result).to include(
        access_token: "github-access-token",
        token_type: "bearer",
        scope: "user:email"
      )

      expect(Clavis::Logging).to have_received(:log_token_exchange).with(:github, true)
    end

    context "when the token exchange fails" do
      let(:error_response) do
        instance_double(
          Faraday::Response,
          status: 400,
          body: {
            error: "bad_verification_code",
            error_description: "The code passed is incorrect or expired."
          }.to_json
        )
      end

      before do
        allow(http_client).to receive(:post).and_return(error_response)
        allow(provider).to receive(:handle_token_error_response).and_raise(Clavis::InvalidGrant)
      end

      it "handles the error response" do
        expect { provider.token_exchange(code: "invalid-code") }.to raise_error(Clavis::InvalidGrant)
        expect(Clavis::Logging).to have_received(:log_token_exchange).with(:github, false)
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

  describe "#get_user_info" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:access_token) { "github-access-token" }
    let(:user_response_body) do
      {
        id: 123_456,
        login: "testuser",
        name: "Test User",
        email: "public@example.com",
        avatar_url: "https://github.com/images/avatar.jpg"
      }.to_json
    end
    let(:user_response) { instance_double(Faraday::Response, status: 200, body: user_response_body, env: double(request: double(headers: { "Authorization" => "Bearer #{access_token}" }))) }

    let(:emails_response_body) do
      [
        {
          email: "private@example.com",
          primary: true,
          verified: true
        },
        {
          email: "public@example.com",
          primary: false,
          verified: true
        }
      ].to_json
    end
    let(:emails_response) { instance_double(Faraday::Response, status: 200, body: emails_response_body) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).with("https://api.github.com/user", any_args).and_return(user_response)
      allow(http_client).to receive(:get).with("https://api.github.com/user/emails", any_args).and_return(emails_response)
      allow(Clavis::Logging).to receive(:log_userinfo_request)
      allow(Clavis::Security::InputValidator).to receive(:valid_token?).and_return(true)
    end

    it "fetches user info from GitHub" do
      result = provider.get_user_info(access_token)

      expect(http_client).to have_received(:get).with("https://api.github.com/user") do |&block|
        req = double
        expect(req).to receive(:headers).and_return({})
        block.call(req)
      end

      expect(result).to include(
        id: "123456",
        name: "Test User",
        nickname: "testuser",
        email: "private@example.com",
        email_verified: true,
        image: "https://github.com/images/avatar.jpg"
      )

      expect(Clavis::Logging).to have_received(:log_userinfo_request).with(:github, true)
    end

    context "when the user info request fails" do
      let(:error_response) do
        instance_double(
          Faraday::Response,
          status: 401,
          body: {
            message: "Bad credentials"
          }.to_json
        )
      end

      before do
        allow(http_client).to receive(:get).with("https://api.github.com/user", any_args).and_return(error_response)
        allow(provider).to receive(:handle_userinfo_error_response).and_raise(Clavis::InvalidToken)
      end

      it "handles the error response" do
        expect { provider.get_user_info(access_token) }.to raise_error(Clavis::InvalidToken)
        expect(Clavis::Logging).to have_received(:log_userinfo_request).with(:github, false)
      end
    end

    context "when the emails request fails" do
      let(:emails_error_response) do
        instance_double(
          Faraday::Response,
          status: 404,
          body: {
            message: "Not Found"
          }.to_json
        )
      end

      before do
        allow(http_client).to receive(:get).with("https://api.github.com/user/emails", any_args).and_return(emails_error_response)
      end

      it "still returns user info with the public email" do
        result = provider.get_user_info(access_token)
        expect(result[:email]).to eq("public@example.com")
      end
    end

    context "when both email endpoints return no data" do
      let(:user_response_body_no_email) do
        {
          id: 123_456,
          login: "testuser",
          name: "Test User",
          avatar_url: "https://github.com/images/avatar.jpg"
        }.to_json
      end
      let(:user_response_no_email) { instance_double(Faraday::Response, status: 200, body: user_response_body_no_email, env: double(request: double(headers: { "Authorization" => "Bearer #{access_token}" }))) }
      let(:emails_response_no_data) { instance_double(Faraday::Response, status: 200, body: "[]") }

      before do
        allow(http_client).to receive(:get).with("https://api.github.com/user", any_args).and_return(user_response_no_email)
        allow(http_client).to receive(:get).with("https://api.github.com/user/emails", any_args).and_return(emails_response_no_data)
      end

      it "returns user info with nil email" do
        result = provider.get_user_info(access_token)
        expect(result[:email]).to be_nil
      end
    end
  end

  describe "#refresh_token" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:refresh_token) { "github-refresh-token" }
    let(:response_body) do
      {
        access_token: "new-github-access-token",
        token_type: "bearer",
        scope: "user:email"
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
                                                                                      access_token: "new-github-access-token",
                                                                                      token_type: "bearer",
                                                                                      scope: "user:email"
                                                                                    })
    end

    it "refreshes the token successfully" do
      result = provider.refresh_token(refresh_token)

      expect(http_client).to have_received(:post).with(
        "https://github.com/login/oauth/access_token",
        {
          grant_type: "refresh_token",
          refresh_token: refresh_token,
          client_id: "test-client-id",
          client_secret: "test-client-secret"
        }
      )

      expect(result).to include(
        access_token: "new-github-access-token"
      )

      expect(Clavis::Logging).to have_received(:log_token_refresh).with(:github, true)
    end

    context "when the token refresh fails" do
      let(:error_response) do
        instance_double(
          Faraday::Response,
          status: 400,
          body: {
            error: "invalid_grant",
            error_description: "The refresh token is invalid or has expired."
          }.to_json
        )
      end

      before do
        allow(http_client).to receive(:post).and_return(error_response)
        allow(provider).to receive(:handle_token_error_response).and_raise(Clavis::InvalidGrant)
      end

      it "handles the error response" do
        expect { provider.refresh_token(refresh_token) }.to raise_error(Clavis::InvalidGrant)
        expect(Clavis::Logging).to have_received(:log_token_refresh).with(:github, false)
      end
    end
  end
end
