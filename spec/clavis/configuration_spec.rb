# frozen_string_literal: true

RSpec.describe Clavis::Configuration do
  let(:configuration) { Clavis::Configuration.new }

  describe "#initialize" do
    it "sets default values" do
      expect(configuration.providers).to eq({})
      expect(configuration.default_callback_path).to eq("/auth/:provider/callback")
      expect(configuration.default_scopes).to be_nil
      expect(configuration.verbose_logging).to be false
      expect(configuration.claims_processor).to be_nil
    end
  end

  describe "#provider_configured?" do
    context "when provider is not configured" do
      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when providers hash is nil" do
      before do
        configuration.providers = nil
      end

      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when providers hash is empty" do
      before do
        configuration.providers = {}
      end

      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when provider config is invalid (not a hash)" do
      before do
        configuration.providers = {
          google: "not-a-hash"
        }
      end

      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when provider is configured" do
      before do
        configuration.providers = {
          google: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            redirect_uri: "/auth/google/callback"
          }
        }
      end

      it "returns true with symbol provider name" do
        expect(configuration.provider_configured?(:google)).to be true
      end

      it "returns true with string provider name" do
        expect(configuration.provider_configured?("google")).to be true
      end
    end

    context "when provider has empty client_id" do
      before do
        configuration.providers = {
          google: {
            client_id: "",
            client_secret: "test-client-secret",
            redirect_uri: "/callback/google"
          }
        }
      end

      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when provider has nil client_id" do
      before do
        configuration.providers = {
          google: {
            client_id: nil,
            client_secret: "test-client-secret",
            redirect_uri: "/callback/google"
          }
        }
      end

      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when provider has whitespace-only client_id" do
      before do
        configuration.providers = {
          google: {
            client_id: "   ",
            client_secret: "test-client-secret",
            redirect_uri: "/callback/google"
          }
        }
      end

      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when provider is missing client_id" do
      before do
        configuration.providers = {
          google: {
            client_secret: "test-client-secret"
          }
        }
      end

      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when provider is missing client_secret" do
      before do
        configuration.providers = {
          google: {
            client_id: "test-client-id"
          }
        }
      end

      it "returns false" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end

    context "when provider is apple" do
      before do
        configuration.providers = {
          apple: {
            client_id: "test-client-id",
            client_secret: "test-client-secret"
            # No redirect_uri
          }
        }
      end

      it "allows missing redirect_uri for apple" do
        expect(configuration.provider_configured?(:apple)).to be true
      end
    end

    context "when provider is not apple and missing redirect_uri" do
      before do
        configuration.providers = {
          google: {
            client_id: "test-client-id",
            client_secret: "test-client-secret"
            # No redirect_uri
          }
        }
      end

      it "returns false for non-apple providers without redirect_uri" do
        expect(configuration.provider_configured?(:google)).to be false
      end
    end
  end

  describe "#validate_provider!" do
    context "when provider is not configured" do
      it "raises ProviderNotConfigured error" do
        expect { configuration.validate_provider!(:google) }.to raise_error(Clavis::ProviderNotConfigured)
      end
    end

    context "when provider is configured" do
      before do
        configuration.providers = {
          google: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            redirect_uri: "/auth/google/callback"
          }
        }
      end

      it "does not raise an error" do
        expect { configuration.validate_provider!(:google) }.not_to raise_error
      end
    end
  end

  describe "#provider_config" do
    context "when provider is not configured" do
      it "raises ProviderNotConfigured error" do
        expect { configuration.provider_config(:google) }.to raise_error(Clavis::ProviderNotConfigured)
      end
    end

    context "when provider is configured" do
      let(:provider_config) do
        {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "/auth/google/callback"
        }
      end

      before do
        # Disable Rails credentials usage
        configuration.use_rails_credentials = false
        configuration.providers = { google: provider_config }
      end

      it "returns the provider configuration" do
        expect(configuration.provider_config(:google)).to eq(provider_config)
      end
    end
  end

  describe "#callback_path" do
    context "when provider has a custom redirect_uri" do
      before do
        configuration.providers = {
          google: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            redirect_uri: "https://example.com/custom/callback"
          }
        }
      end

      it "returns the custom redirect_uri" do
        expect(configuration.callback_path(:google)).to eq("https://example.com/custom/callback")
      end
    end

    context "when provider uses the default callback path" do
      before do
        # Set the provider configuration with a nil redirect_uri to force using default
        configuration.providers = {
          google: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            redirect_uri: nil
          }
        }

        # Set default_callback_path
        configuration.default_callback_path = "/auth/:provider/callback"

        # Stub the validation to avoid errors
        allow(configuration).to receive(:validate_provider!).and_return(true)
        allow(configuration).to receive(:provider_config).and_return({ redirect_uri: nil })
      end

      it "returns the default callback path with the provider name" do
        expect(configuration.callback_path(:google)).to eq("/auth/google/callback")
      end
    end

    context "when provider name is a string instead of symbol" do
      before do
        configuration.providers = {
          google: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            redirect_uri: "https://example.com/custom/callback"
          }
        }
      end

      it "handles string provider names" do
        expect(configuration.callback_path("google")).to eq("https://example.com/custom/callback")
      end
    end

    context "when provider has placeholder in redirect URI" do
      before do
        configuration.providers = {
          github: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            redirect_uri: "/auth/:provider/custom"
          }
        }
      end

      it "replaces the :provider placeholder" do
        expect(configuration.callback_path(:github)).to eq("/auth/github/custom")
      end
    end

    context "when no placeholder in redirect URI" do
      before do
        configuration.providers = {
          github: {
            client_id: "test-client-id",
            client_secret: "test-client-secret",
            redirect_uri: "/static/path"
          }
        }
      end

      it "returns the URI unchanged" do
        expect(configuration.callback_path(:github)).to eq("/static/path")
      end
    end
  end
end
