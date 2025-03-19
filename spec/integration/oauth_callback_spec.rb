# frozen_string_literal: true

require "spec_helper"
require "action_controller"

# Create a base class for our test controller
class TestActionController
  attr_accessor :params, :session

  def initialize
    @params = {}
    @session = {}
  end

  def redirect_to(path)
    # This is just a stub for testing
    @redirect_path = path
  end

  attr_reader :redirect_path
end

class DummyUser
  attr_accessor :email, :name, :oauth_identities

  def initialize(attrs = {})
    @email = attrs[:email]
    @name = attrs[:name]
    @oauth_identities = []
  end

  def self.find_or_create_from_oauth_identity(auth_hash)
    new(
      email: auth_hash.dig(:info, :email),
      name: auth_hash.dig(:info, :name)
    )
  end

  def save
    true
  end
end

class DummySessionsController < TestActionController
  def new
    # Just a stub
  end
end

# Use existing mock ActiveRecord from our support/mocks.rb
# Create a mock for the OauthIdentity class
module Clavis
  class OauthIdentity
    attr_accessor :provider, :uid, :user, :token, :refresh_token, :expires_at, :auth_data

    def initialize(attributes = {})
      attributes.each do |key, value|
        send(:"#{key}=", value) if respond_to?(:"#{key}=")
      end
      @auth_data = {}
    end

    def self.find_or_initialize_by(attributes)
      new(attributes)
    end

    def new_record?
      true
    end

    def save!
      true
    end

    def update(attributes)
      attributes.each do |key, value|
        send(:"#{key}=", value) if respond_to?(:"#{key}=")
      end
      true
    end
  end
end

# Create a test user class
class DummyUser
  attr_accessor :id, :email, :name, :oauth_identities, :changed

  def initialize(attrs = {})
    @id = rand(1000)
    @email = attrs[:email]
    @name = attrs[:name]
    @oauth_identities = []
    @changed = false
  end

  def self.find_or_create_from_oauth_identity(auth_hash)
    new(
      email: auth_hash.dig(:info, :email),
      name: auth_hash.dig(:info, :name)
    )
  end

  def add_oauth_identity(auth_hash)
    identity = Clavis::OauthIdentity.new(
      provider: auth_hash[:provider],
      uid: auth_hash[:uid],
      user: self,
      token: auth_hash.dig(:credentials, :token),
      refresh_token: auth_hash.dig(:credentials, :refresh_token),
      expires_at: auth_hash.dig(:credentials, :expires_at) ? Time.at(auth_hash.dig(:credentials, :expires_at)) : nil,
      auth_data: auth_hash[:info]
    )
    @oauth_identities << identity
    identity
  end

  def oauth_identity_for(provider)
    @oauth_identities.find { |identity| identity.provider.to_s == provider.to_s }
  end

  def connected_to?(provider)
    oauth_identity_for(provider).present?
  end

  def save!
    true
  end

  def save
    true
  end

  def changed?
    @changed
  end
end

# Create a mock controller
class MockController
  attr_accessor :params, :session

  def initialize
    @params = {}
    @session = {}
    @redirect_path = nil
  end

  def redirect_to(path, _options = {})
    @redirect_path = path
  end

  attr_reader :redirect_path
end

RSpec.describe "OAuth Callback Integration" do
  let(:auth_code) { "4/0AXEFSeXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" }

  let(:processed_auth_hash) do
    {
      provider: :google,
      uid: "112233445566778899000",
      info: {
        name: "John Doe",
        email: "example@example.com",
        image: "https://example.com/profile_picture.jpg"
      },
      credentials: {
        token: "ya29.a0AfB_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        refresh_token: "1//XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        expires_at: Time.now.to_i + 3600
      }
    }
  end

  before do
    # Configure Clavis providers
    allow(Clavis).to receive_message_chain(:configuration, :providers).and_return({
                                                                                    google: {
                                                                                      client_id: "fake-client-id-123456789.apps.googleusercontent.com",
                                                                                      client_secret: "fake-client-secret-XXXXXXXXXXXXXXXX",
                                                                                      redirect_uri: "http://localhost:3000/auth/google/callback"
                                                                                    }
                                                                                  })

    # Mock the provider creation
    mock_provider = double("GoogleProvider")
    allow(mock_provider).to receive(:process_callback).and_return(processed_auth_hash)
    allow(Clavis).to receive(:provider).and_return(mock_provider)

    # Mock state validation
    allow(Clavis::Security::SessionManager).to receive(:valid_state?).and_return(true)

    # Add a helper method to retrieve configuration
    Clavis.singleton_class.class_eval do
      unless respond_to?(:provider_config)
        define_method(:provider_config) do |provider_name|
          configuration.providers[provider_name.to_sym]
        end
      end
    end
  end

  it "processes OAuth callback successfully" do
    # Create a mock controller
    controller = MockController.new
    controller.params = {
      provider: "google",
      code: auth_code,
      state: "valid-state"
    }

    # Process the callback
    provider_name = controller.params[:provider].to_sym
    code = controller.params[:code]
    state = controller.params[:state]

    # Verify state
    expect(Clavis::Security::SessionManager.valid_state?(controller.session, state)).to be true

    # Get provider
    provider = Clavis.provider(provider_name)

    # Exchange code for token
    auth_hash = provider.process_callback(code)

    # Verify the auth hash
    expect(auth_hash[:provider]).to eq(:google)
    expect(auth_hash[:uid]).to eq("112233445566778899000")
    expect(auth_hash[:info][:email]).to eq("example@example.com")

    # Set up a default redirect URI
    redirect_uri = "/dashboard"
    controller.redirect_to(redirect_uri)

    # Verify redirect
    expect(controller.redirect_path).to eq("/dashboard")
  end
end
