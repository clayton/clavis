# frozen_string_literal: true

RSpec.describe Clavis do
  it "has a version number" do
    expect(Clavis::VERSION).not_to be nil
  end

  describe ".configuration" do
    it "returns a Configuration instance" do
      expect(Clavis.configuration).to be_a(Clavis::Configuration)
    end
  end

  describe ".configure" do
    it "yields the configuration" do
      expect { |b| Clavis.configure(&b) }.to yield_with_args(Clavis.configuration)
    end
  end

  describe ".reset_configuration!" do
    it "resets the configuration" do
      original_config = Clavis.configuration
      Clavis.configuration.providers = { test: { client_id: "test" } }

      Clavis.reset_configuration!

      expect(Clavis.configuration).not_to eq(original_config)
      expect(Clavis.configuration.providers).to eq({})
    end
  end

  describe ".register_provider" do
    it "registers a provider" do
      provider_class = Class.new
      Clavis.register_provider(:test, provider_class)

      expect(Clavis.provider_registry[:test]).to eq(provider_class)
    end
  end
end
