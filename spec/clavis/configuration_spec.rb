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

    context "when provider is configured" do
      before do
        configuration.providers = {
          google: {
            client_id: "test-client-id",
            client_secret: "test-client-secret"
          }
        }
      end

      it "returns true" do
        expect(configuration.provider_configured?(:google)).to be true
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
            client_secret: "test-client-secret"
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
          client_secret: "test-client-secret"
        }
      end

      before do
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
        configuration.providers = {
          google: {
            client_id: "test-client-id",
            client_secret: "test-client-secret"
          }
        }
      end

      it "returns the default callback path with the provider name" do
        expect(configuration.callback_path(:google)).to eq("/auth/google/callback")
      end
    end
  end
end
