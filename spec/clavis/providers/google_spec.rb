# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::Providers::Google do
  let(:config) do
    {
      client_id: "test-client-id",
      client_secret: "test-client-secret",
      redirect_uri: "https://example.com/auth/google/callback"
    }
  end

  let(:provider) { described_class.new(config) }

  describe "#initialize" do
    it "sets the client_id, client_secret, and redirect_uri" do
      expect(provider.client_id).to eq("test-client-id")
      expect(provider.client_secret).to eq("test-client-secret")
      expect(provider.redirect_uri).to eq("https://example.com/auth/google/callback")
    end

    it "sets default configuration values" do
      expect(provider.instance_variable_get(:@jwt_leeway)).to eq(60)
      expect(provider.instance_variable_get(:@token_verification_enabled)).to be true
      expect(provider.instance_variable_get(:@hosted_domain)).to be_nil
    end

    it "allows configuring jwt_leeway" do
      custom_provider = described_class.new(config.merge(jwt_leeway: 120))
      expect(custom_provider.instance_variable_get(:@jwt_leeway)).to eq(120)
    end

    it "allows configuring hosted_domain" do
      custom_provider = described_class.new(config.merge(hosted_domain: "example.com"))
      expect(custom_provider.instance_variable_get(:@hosted_domain)).to eq("example.com")
      expect(custom_provider.instance_variable_get(:@allowed_hosted_domains)).to eq(["example.com"])
    end

    it "allows disabling token verification" do
      custom_provider = described_class.new(config.merge(verify_tokens: false))
      expect(custom_provider.instance_variable_get(:@token_verification_enabled)).to be false
    end

    context "when configuration is missing" do
      it "raises an error when client_id is missing" do
        config.delete(:client_id)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end

      it "raises an error when client_secret is missing" do
        config.delete(:client_secret)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end

      it "raises an error when redirect_uri is missing" do
        config.delete(:redirect_uri)
        expect { described_class.new(config) }.to raise_error(Clavis::MissingConfiguration)
      end
    end
  end

  describe "#provider_name" do
    it "returns :google" do
      expect(provider.provider_name).to eq(:google)
    end
  end

  describe "#authorization_endpoint" do
    it "returns the Google authorization endpoint" do
      expect(provider.authorization_endpoint).to eq("https://accounts.google.com/o/oauth2/v2/auth")
    end
  end

  describe "#token_endpoint" do
    it "returns the Google token endpoint" do
      expect(provider.token_endpoint).to eq("https://oauth2.googleapis.com/token")
    end
  end

  describe "#userinfo_endpoint" do
    it "returns the Google userinfo endpoint" do
      expect(provider.userinfo_endpoint).to eq("https://www.googleapis.com/oauth2/v3/userinfo")
    end
  end

  describe "#tokeninfo_endpoint" do
    it "returns the Google tokeninfo endpoint" do
      expect(provider.tokeninfo_endpoint).to eq("https://www.googleapis.com/oauth2/v3/tokeninfo")
    end
  end

  describe "#default_scopes" do
    it "returns the default scopes for Google" do
      expect(provider.default_scopes).to eq("openid email profile")
    end
  end

  describe "#openid_provider?" do
    it "returns true" do
      expect(provider.openid_provider?).to be true
    end
  end

  describe "#normalize_scopes" do
    it "returns default scopes for nil or empty input" do
      expect(provider.normalize_scopes(nil)).to eq("openid email profile")
      expect(provider.normalize_scopes("")).to eq("openid email profile")
    end

    it "handles space-delimited scopes" do
      expect(provider.normalize_scopes("openid email")).to eq("openid email profile")
    end

    it "handles comma-delimited scopes" do
      expect(provider.normalize_scopes("openid,email")).to eq("openid email profile")
    end

    it "adds default base scopes if missing" do
      expect(provider.normalize_scopes("calendar")).to eq("calendar openid email profile")
    end

    it "removes duplicate scopes" do
      expect(provider.normalize_scopes("email email profile calendar")).to eq("email profile calendar openid")
    end
  end

  describe "#authorize_url" do
    it "includes the required parameters" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to start_with("https://accounts.google.com/o/oauth2/v2/auth")
      expect(url).to include("response_type=code")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgoogle%2Fcallback")
      expect(url).to include("scope=openid+email+profile")
      expect(url).to include("state=test-state")
      expect(url).to include("nonce=test-nonce")
    end

    it "includes access_type=offline and prompt=consent for refresh token support" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to include("access_type=offline")
      expect(url).to include("prompt=consent")
    end

    it "allows custom scopes" do
      url = provider.authorize_url(state: "test-state", nonce: "test-nonce", scope: "openid email")

      expect(url).to include("scope=openid+email+profile")
    end

    it "includes login_hint when provided" do
      url = provider.authorize_url(
        state: "test-state",
        nonce: "test-nonce",
        login_hint: "user@example.com"
      )

      expect(url).to include("login_hint=user%40example.com")
    end

    it "allows overriding prompt parameter" do
      url = provider.authorize_url(
        state: "test-state",
        nonce: "test-nonce",
        prompt: "select_account"
      )

      expect(url).to include("prompt=select_account")
    end

    it "includes hd parameter when hosted_domain is configured" do
      custom_provider = described_class.new(config.merge(hosted_domain: "example.com"))
      url = custom_provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).to include("hd=example.com")
    end

    it "doesn't include hd parameter when hosted_domain is wildcard" do
      custom_provider = described_class.new(config.merge(hosted_domain: "*"))
      url = custom_provider.authorize_url(state: "test-state", nonce: "test-nonce")

      expect(url).not_to include("hd=")
    end
  end

  describe "#verify_id_token" do
    # Since verify_id_token is an implementation detail that handles JWTs,
    # we'll test its behavior from the outside rather than the internal details

    it "returns an empty hash for nil or empty tokens" do
      expect(provider.verify_id_token(nil)).to eq({})
      expect(provider.verify_id_token("")).to eq({})
    end

    it "raises an error for invalid tokens" do
      # This isn't even a real JWT, so it should fail parsing
      expect { provider.verify_id_token("not-a-real-token") }.to raise_error(Clavis::InvalidToken)
    end
  end

  describe "#verify_token" do
    let(:access_token) { "test-access-token" }
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response) { instance_double(Faraday::Response) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_yield(double("request", params: {})).and_return(response)
      allow(Clavis::Logging).to receive(:log_token_verification)
    end

    context "when token verification succeeds" do
      before do
        allow(response).to receive(:status).and_return(200)
        allow(response).to receive(:body).and_return({ aud: "test-client-id" }.to_json)
      end

      it "returns true" do
        expect(provider.verify_token(access_token)).to be true
      end

      it "logs success" do
        provider.verify_token(access_token)
        expect(Clavis::Logging).to have_received(:log_token_verification).with(:google, true)
      end
    end

    context "when token verification fails" do
      before do
        allow(response).to receive(:status).and_return(400)
      end

      it "returns false" do
        expect(provider.verify_token(access_token)).to be false
      end

      it "logs failure" do
        provider.verify_token(access_token)
        expect(Clavis::Logging).to have_received(:log_token_verification).with(:google, false, "Token info response: 400")
      end
    end

    context "when audience doesn't match" do
      before do
        allow(response).to receive(:status).and_return(200)
        allow(response).to receive(:body).and_return({ aud: "wrong-client-id" }.to_json)
      end

      it "returns false" do
        expect(provider.verify_token(access_token)).to be false
      end

      it "logs audience mismatch" do
        provider.verify_token(access_token)
        expect(Clavis::Logging).to have_received(:log_token_verification).with(:google, false, "Token audience mismatch")
      end
    end

    context "when token verification is disabled" do
      let(:provider_with_disabled_verification) do
        described_class.new(config.merge(verify_tokens: false))
      end

      it "returns false without making a request" do
        expect(provider_with_disabled_verification.verify_token(access_token)).to be false
        expect(http_client).not_to have_received(:get)
      end
    end
  end

  describe "#verify_hosted_domain" do
    let(:user_info) { { email: "user@example.com", hd: "example.com" } }

    context "when no hosted domain is configured" do
      it "returns true without validation" do
        expect(provider.verify_hosted_domain(user_info)).to be true
      end
    end

    context "when wildcard hosted domain is configured" do
      let(:wildcard_provider) { described_class.new(config.merge(hosted_domain: "*")) }

      it "returns true for any domain" do
        expect(wildcard_provider.verify_hosted_domain(user_info)).to be true
      end
    end

    context "when specific hosted domain is configured" do
      let(:domain_provider) { described_class.new(config.merge(hosted_domain: "example.com")) }

      it "returns true when domains match" do
        expect(domain_provider.verify_hosted_domain(user_info)).to be true
      end

      it "raises InvalidHostedDomain when domains don't match" do
        wrong_domain_info = { email: "user@wrong.com", hd: "wrong.com" }
        expect { domain_provider.verify_hosted_domain(wrong_domain_info) }
          .to raise_error(Clavis::InvalidHostedDomain)
      end

      it "raises InvalidHostedDomain when hd is missing" do
        missing_hd_info = { email: "user@example.com" }
        expect { domain_provider.verify_hosted_domain(missing_hd_info) }
          .to raise_error(Clavis::InvalidHostedDomain)
      end
    end

    context "when multiple hosted domains are configured" do
      let(:multi_domain_provider) { described_class.new(config.merge(hosted_domain: ["example.com", "example.org"])) }

      it "returns true when domain is in the allowed list" do
        expect(multi_domain_provider.verify_hosted_domain(user_info)).to be true

        other_domain_info = { email: "user@example.org", hd: "example.org" }
        expect(multi_domain_provider.verify_hosted_domain(other_domain_info)).to be true
      end

      it "raises InvalidHostedDomain when domain is not in the allowed list" do
        wrong_domain_info = { email: "user@wrong.com", hd: "wrong.com" }
        expect { multi_domain_provider.verify_hosted_domain(wrong_domain_info) }
          .to raise_error(Clavis::InvalidHostedDomain)
      end
    end
  end

  describe "#get_user_info" do
    let(:access_token) { "test-access-token" }
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response) { instance_double(Faraday::Response) }
    let(:request) { double("request", headers: {}) }

    before do
      allow(provider).to receive(:http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_yield(request).and_return(response)
      allow(response).to receive(:status).and_return(200)
      allow(response).to receive(:body).and_return({
        sub: "123456789",
        email: "test@example.com",
        email_verified: true,
        name: "Test User",
        given_name: "Test",
        family_name: "User",
        picture: "https://example.com/photo.jpg",
        hd: "example.com"
      }.to_json)

      # Mock token verification to succeed
      allow(provider).to receive(:verify_token).and_return(true)
      allow(Clavis::Logging).to receive(:log_userinfo_request)
    end

    it "calls token verification" do
      provider.get_user_info(access_token)
      expect(provider).to have_received(:verify_token).with(access_token)
    end

    it "raises InvalidToken if token verification fails" do
      allow(provider).to receive(:verify_token).and_return(false)
      expect { provider.get_user_info(access_token) }.to raise_error(Clavis::InvalidToken)
    end

    it "verifies hosted domain if configured" do
      domain_provider = described_class.new(config.merge(hosted_domain: "example.com"))
      allow(domain_provider).to receive(:http_client).and_return(http_client)
      allow(domain_provider).to receive(:verify_token).and_return(true)

      domain_provider.get_user_info(access_token)
      # Should not raise an error since the domain matches
    end

    it "processes the user info response" do
      result = provider.get_user_info(access_token)

      expect(result).to include(
        sub: "123456789",
        email: "test@example.com",
        name: "Test User",
        hd: "example.com"
      )
    end
  end

  describe "#token_exchange" do
    let(:http_client) { instance_double(Faraday::Connection) }
    let(:response_body) do
      {
        access_token: "test-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "test-refresh-token",
        id_token: "test-id-token"
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

      expect(result).to include(
        access_token: "test-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "test-refresh-token",
        id_token: "test-id-token"
      )
    end
  end
end
