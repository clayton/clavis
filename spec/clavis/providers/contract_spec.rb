# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Provider Contract" do
  # Define methods and classes in a shared context
  before(:all) do
    @required_methods = %i[
      process_callback
      authorize_url
      token_exchange
      get_user_info
      refresh_token
      provider_name
      authorization_endpoint
      token_endpoint
      userinfo_endpoint
      default_scopes
      openid_provider?
    ]

    @provider_classes = [
      Clavis::Providers::Google,
      Clavis::Providers::Github,
      Clavis::Providers::Microsoft,
      Clavis::Providers::Facebook,
      Clavis::Providers::Generic
    ]

    # Set up additional config for Apple provider
    apple_config = {
      client_id: "fake-client-id",
      client_secret: "fake-client-secret",
      redirect_uri: "http://localhost:3000/callback",
      team_id: "fake-team-id",
      key_id: "fake-key-id",
      private_key: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\nOF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n-----END PRIVATE KEY-----"
    }

    @required_arguments = {
      client_id: "fake-client-id",
      client_secret: "fake-client-secret",
      redirect_uri: "http://localhost:3000/callback"
    }

    @provider_specific_config = {
      Clavis::Providers::Apple => apple_config
    }
  end

  # Iterate through each provider class
  it "ensures all provider classes implement the required methods" do
    @provider_classes.each do |provider_class|
      config = @provider_specific_config[provider_class] || @required_arguments
      provider = provider_class.new(config)

      @required_methods.each do |method_name|
        expect(provider).to respond_to(method_name),
                            "Expected #{provider_class.name} to implement method: #{method_name}"
      end

      # Test initialization with required arguments
      expect { provider_class.new(config) }.not_to raise_error

      # Test required arguments (skip for providers with custom configs)
      unless @provider_specific_config.key?(provider_class)
        %i[client_id client_secret redirect_uri].each do |arg|
          args = @required_arguments.dup
          args.delete(arg)
          expect { provider_class.new(args) }.to raise_error(Clavis::MissingConfiguration)
        end
      end

      # Check provider_name is a symbol
      expect(provider.provider_name).to be_a(Symbol)

      # Check endpoints
      unless provider_class == Clavis::Providers::Generic
        expect(provider.authorization_endpoint).to be_a(String)
        expect(provider.token_endpoint).to be_a(String)

        # Some providers might not have userinfo endpoints
        expect(provider.userinfo_endpoint).to be_a(String) if provider.userinfo_endpoint
      end

      # Check authorize_url
      if provider_class == Clavis::Providers::Apple
        # Apple requires special handling due to client_secret generation
        expect { provider.authorize_url(state: SecureRandom.hex(16), nonce: SecureRandom.hex(16)) }.not_to raise_error
      else
        expect { provider.authorize_url }.to raise_error(ArgumentError)

        # Test with valid arguments
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        url = nil
        expect { url = provider.authorize_url(state: state, nonce: nonce) }.not_to raise_error

        expect(url).to be_a(String)
        expect(url).to start_with("http")
      end
    end

    # Add Apple provider test separately with correct configuration
    apple_config = @provider_specific_config[Clavis::Providers::Apple]
    apple_provider = Clavis::Providers::Apple.new(apple_config)

    @required_methods.each do |method_name|
      expect(apple_provider).to respond_to(method_name),
                                "Expected Apple provider to implement method: #{method_name}"
    end

    expect(apple_provider.provider_name).to eq(:apple)
    expect(apple_provider.authorization_endpoint).to be_a(String)
    expect(apple_provider.token_endpoint).to be_a(String)
    expect(apple_provider.userinfo_endpoint).to be_nil # Apple has no userinfo endpoint

    # For Apple, check that userinfo endpoint method exists but returns nil
    expect(apple_provider.userinfo_endpoint).to be_nil
    expect { apple_provider.get_user_info("test_token") }.to raise_error(Clavis::UnsupportedOperation)

    # Check that refresh token method exists but raises UnsupportedOperation
    expect { apple_provider.refresh_token("test_refresh_token") }.to raise_error(Clavis::UnsupportedOperation)
  end
end
