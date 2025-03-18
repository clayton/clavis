# frozen_string_literal: true

require "spec_helper"
require "ostruct"

# Define structs outside of blocks
RequestStruct = Struct.new(:url)

# Simplified test for the authentication module without requiring a full Rails setup
RSpec.describe "Clavis Authentication Module", type: :model do
  before do
    # Configure Clavis for testing
    Clavis.configure do |c|
      c.providers = {
        google: {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "http://localhost:3000/auth/google/callback"
        }
      }
    end
  end

  describe "Provider functionality" do
    it "validates provider configuration" do
      expect(Clavis.configuration.provider_configured?(:google)).to be true
      expect(Clavis.configuration.provider_configured?(:unknown)).to be false
    end

    it "retrieves provider configuration" do
      config = Clavis.configuration.providers[:google]
      expect(config[:client_id]).to eq("test-client-id")
      expect(config[:redirect_uri]).to eq("http://localhost:3000/auth/google/callback")
    end

    it "raises error for invalid providers" do
      expect { Clavis.provider(:unsupported_provider) }.to raise_error(Clavis::UnsupportedProvider)
    end
  end

  describe "Authentication functionality" do
    let(:module_instance) do
      Class.new do
        include Clavis::Controllers::Concerns::Authentication

        attr_accessor :session, :params, :request

        def initialize
          @session = {}
          @params = {}
          @request = RequestStruct.new("http://test.com")
        end

        def redirect_to(url, options = {})
          { url: url, options: options }
        end
      end.new
    end

    it "exposes the oauth_authorize method" do
      expect(module_instance).to respond_to(:oauth_authorize)
    end

    it "exposes the oauth_callback method" do
      expect(module_instance).to respond_to(:oauth_callback)
    end
  end
end
