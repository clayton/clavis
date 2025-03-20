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

    context "with GitHub Enterprise configuration" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/github/callback",
          authorize_url: "https://github.enterprise.com/login/oauth/authorize"
        }
      end

      it "returns the custom GitHub Enterprise authorization endpoint" do
        expect(provider.authorization_endpoint).to eq("https://github.enterprise.com/login/oauth/authorize")
      end
    end
  end

  describe "#token_endpoint" do
    it "returns the GitHub token endpoint" do
      expect(provider.token_endpoint).to eq("https://github.com/login/oauth/access_token")
    end

    context "with GitHub Enterprise configuration" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/github/callback",
          token_url: "https://github.enterprise.com/login/oauth/access_token"
        }
      end

      it "returns the custom GitHub Enterprise token endpoint" do
        expect(provider.token_endpoint).to eq("https://github.enterprise.com/login/oauth/access_token")
      end
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the GitHub userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://api.github.com/user")
    end

    context "with GitHub Enterprise configuration" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/github/callback",
          site_url: "https://api.github.enterprise.com"
        }
      end

      it "returns the custom GitHub Enterprise userinfo endpoint" do
        expect(provider.userinfo_endpoint).to eq("https://api.github.enterprise.com/user")
      end
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
    let(:request_double) { double("request", headers: {}) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).with("https://api.github.com/user", any_args).and_yield(request_double).and_return(user_response)
      allow(http_client).to receive(:get).with("https://api.github.com/user/emails", any_args).and_yield(request_double).and_return(emails_response)
      allow(Clavis::Logging).to receive(:log_userinfo_request)
      allow(Clavis::Logging).to receive(:log_custom)
      allow(Clavis::Security::InputValidator).to receive(:valid_token?).and_return(true)
    end

    it "fetches user info from GitHub" do
      result = provider.get_user_info(access_token)

      expect(http_client).to have_received(:get).with("https://api.github.com/user")

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

    it "sends appropriate API version headers" do
      provider.get_user_info(access_token)

      expect(request_double.headers).to include("Accept" => "application/vnd.github.v3+json")
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
        expect(Clavis::Logging).to have_received(:log_custom).with("github_emails_fetch", false)
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
      let(:emails_response_body_empty) { [].to_json }
      let(:emails_response_empty) { instance_double(Faraday::Response, status: 200, body: emails_response_body_empty) }

      before do
        allow(http_client).to receive(:get).with("https://api.github.com/user", any_args).and_return(user_response_no_email)
        allow(http_client).to receive(:get).with("https://api.github.com/user/emails", any_args).and_return(emails_response_empty)
      end

      it "returns user info with nil email" do
        result = provider.get_user_info(access_token)
        expect(result[:email]).to be_nil
      end
    end

    context "with GitHub Enterprise configuration" do
      let(:config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "https://example.com/auth/github/callback",
          site_url: "https://api.github.enterprise.com"
        }
      end

      before do
        allow(http_client).to receive(:get).with("https://api.github.enterprise.com/user", any_args).and_yield(request_double).and_return(user_response)
        allow(http_client).to receive(:get).with("https://api.github.enterprise.com/user/emails", any_args).and_yield(request_double).and_return(emails_response)
      end

      it "uses the custom API endpoints" do
        provider.get_user_info(access_token)

        expect(http_client).to have_received(:get).with("https://api.github.enterprise.com/user")
        expect(http_client).to have_received(:get).with("https://api.github.enterprise.com/user/emails")
      end
    end
  end

  describe "#find_primary_email" do
    context "with a primary and verified email" do
      let(:emails) do
        [
          { email: "first@example.com", primary: false, verified: true },
          { email: "second@example.com", primary: true, verified: true },
          { email: "third@example.com", primary: false, verified: false }
        ]
      end

      it "returns the primary and verified email" do
        result = provider.send(:find_primary_email, emails)
        expect(result).to eq({ email: "second@example.com", primary: true, verified: true })
      end
    end

    context "with no primary but verified emails" do
      let(:emails) do
        [
          { email: "first@example.com", primary: false, verified: true },
          { email: "second@example.com", primary: false, verified: false }
        ]
      end

      it "returns the first verified email" do
        result = provider.send(:find_primary_email, emails)
        expect(result).to eq({ email: "first@example.com", primary: false, verified: true })
      end
    end

    context "with primary but unverified email" do
      let(:emails) do
        [
          { email: "first@example.com", primary: false, verified: false },
          { email: "second@example.com", primary: true, verified: false }
        ]
      end

      it "returns the primary email" do
        result = provider.send(:find_primary_email, emails)
        expect(result).to eq({ email: "second@example.com", primary: true, verified: false })
      end
    end

    context "with no emails" do
      it "returns nil" do
        result = provider.send(:find_primary_email, [])
        expect(result).to be_nil
      end
    end
  end
end
