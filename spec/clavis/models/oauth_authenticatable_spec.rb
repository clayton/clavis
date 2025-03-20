# frozen_string_literal: true

require "spec_helper"
require "pp" # For pretty printing

RSpec.describe Clavis::Models::OauthAuthenticatable do
  it "is aliased to Clavis::Models::Concerns::OauthAuthenticatable" do
    expect(described_class).to eq(Clavis::Models::Concerns::OauthAuthenticatable)
  end

  it "has the same methods as Clavis::Models::Concerns::OauthAuthenticatable" do
    concern_methods = Clavis::Models::Concerns::OauthAuthenticatable.instance_methods(false)
    alias_methods = described_class.instance_methods(false)

    expect(alias_methods).to match_array(concern_methods)
  end
end

RSpec.describe Clavis::Models::Concerns::OauthAuthenticatable do
  # Create a test class that includes the concern
  # We need to stub the has_many method to avoid errors
  let(:test_class) do
    Class.new do
      # Stub ActiveRecord's has_many method
      def self.has_many(*args); end

      include Clavis::Models::Concerns::OauthAuthenticatable

      attr_accessor :id, :oauth_user

      def initialize(id = 1)
        @id = id
        @oauth_identities = []
        @oauth_user = false
      end

      attr_reader :oauth_identities

      attr_writer :oauth_identities
    end
  end

  let(:user) { test_class.new }

  let(:google_identity) do
    identity = Clavis::OauthIdentity.new
    identity.provider = "google"
    identity.updated_at = Time.now - 172_800 # 2 days in seconds
    # Include both string and symbol keys to test proper handling
    identity.instance_variable_set(:@auth_data, {
                                     "standardized" => {
                                       "email" => "google@example.com",
                                       "name" => "Google User",
                                       "avatar_url" => "https://google.com/avatar.jpg"
                                     },
                                     "name" => "Google User (Raw)",
                                     "email" => "google_raw@example.com",
                                     "image" => "https://google.com/raw-avatar.jpg"
                                   })
    identity
  end

  let(:github_identity) do
    identity = Clavis::OauthIdentity.new
    identity.provider = "github"
    identity.updated_at = Time.now - 86_400 # 1 day in seconds
    # Use symbol keys to test flexibility
    identity.instance_variable_set(:@auth_data, {
                                     standardized: {
                                       email: "github@example.com",
                                       name: "GitHub User",
                                       avatar_url: "https://github.com/avatar.jpg"
                                     },
                                     name: "GitHub User (Raw)",
                                     email: "github_raw@example.com",
                                     picture: "https://github.com/raw-avatar.jpg"
                                   })
    identity
  end

  describe "#oauth_avatar_url" do
    before do
      allow(user).to receive(:oauth_identities).and_return([google_identity, github_identity])
      allow(user).to receive(:oauth_identity).and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("google").and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("github").and_return(github_identity)
    end

    it "prefers standardized data over raw data" do
      expect(user.oauth_avatar_url).to eq("https://google.com/avatar.jpg")
    end

    it "falls back to image field if no standardized data" do
      google_identity.instance_variable_set(:@auth_data, {
                                              "email" => "google@example.com",
                                              "name" => "Google User",
                                              "image" => "https://google.com/fallback-avatar.jpg"
                                            })

      expect(user.oauth_avatar_url).to eq("https://google.com/fallback-avatar.jpg")
    end

    it "falls back to picture field if no image field" do
      google_identity.instance_variable_set(:@auth_data, {
                                              "email" => "google@example.com",
                                              "name" => "Google User",
                                              "picture" => "https://google.com/picture-avatar.jpg"
                                            })

      expect(user.oauth_avatar_url).to eq("https://google.com/picture-avatar.jpg")
    end

    it "returns nil when no identities exist" do
      allow(user).to receive(:oauth_identities).and_return([])
      allow(user).to receive(:oauth_identity).and_return(nil)

      expect(user.oauth_avatar_url).to be_nil
    end

    it "returns nil when identity has no auth_data" do
      identity_without_data = Clavis::OauthIdentity.new(
        provider: "empty",
        auth_data: nil,
        updated_at: Time.now
      )

      allow(user).to receive(:oauth_identity).and_return(identity_without_data)

      expect(user.oauth_avatar_url).to be_nil
    end
  end

  describe "#oauth_name" do
    before do
      allow(user).to receive(:oauth_identities).and_return([google_identity, github_identity])
      allow(user).to receive(:oauth_identity).and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("google").and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("github").and_return(github_identity)
    end

    it "prefers standardized data over raw data" do
      expect(user.oauth_name).to eq("Google User")
    end

    it "falls back to raw data if no standardized data" do
      google_identity.instance_variable_set(:@auth_data, {
                                              "email" => "google@example.com",
                                              "name" => "Google User (Raw)"
                                            })

      expect(user.oauth_name).to eq("Google User (Raw)")
    end

    it "handles both string and symbol keys" do
      # Test with string keys
      google_identity.instance_variable_set(:@auth_data, {
                                              "name" => "String Key User"
                                            })
      expect(user.oauth_name).to eq("String Key User")

      # Test with symbol keys
      google_identity.instance_variable_set(:@auth_data, {
                                              name: "Symbol Key User"
                                            })
      expect(user.oauth_name).to eq("Symbol Key User")
    end
  end

  describe "#oauth_email" do
    before do
      allow(user).to receive(:oauth_identities).and_return([google_identity, github_identity])
      allow(user).to receive(:oauth_identity).and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("google").and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("github").and_return(github_identity)
    end

    it "prefers standardized data over raw data" do
      expect(user.oauth_email).to eq("google@example.com")
    end

    it "falls back to raw data if no standardized data" do
      google_identity.instance_variable_set(:@auth_data, {
                                              "email" => "google_raw@example.com",
                                              "name" => "Google User"
                                            })

      expect(user.oauth_email).to eq("google_raw@example.com")
    end

    it "handles both string and symbol keys" do
      # Test with string keys
      google_identity.instance_variable_set(:@auth_data, {
                                              "email" => "string_key@example.com"
                                            })
      expect(user.oauth_email).to eq("string_key@example.com")

      # Test with symbol keys
      google_identity.instance_variable_set(:@auth_data, {
                                              email: "symbol_key@example.com"
                                            })
      expect(user.oauth_email).to eq("symbol_key@example.com")
    end
  end

  describe "#oauth_user?" do
    context "when the oauth_user flag is true" do
      before do
        user.oauth_user = true
        allow(user).to receive(:oauth_identities).and_return([])
      end

      it "returns true even if no identities exist" do
        expect(user.oauth_user?).to be true
      end
    end

    context "when the user has OAuth identities" do
      before do
        allow(user).to receive(:oauth_identities).and_return([google_identity])
      end

      it "returns true" do
        expect(user.oauth_user?).to be true
      end
    end

    context "when the user has no OAuth identities and flag is false" do
      before do
        user.oauth_user = false
        allow(user).to receive(:oauth_identities).and_return([])
      end

      it "returns false" do
        expect(user.oauth_user?).to be false
      end
    end

    context "with ActiveRecord-like collection" do
      let(:ar_collection) { double("AR Collection") }

      before do
        user.oauth_user = false
        allow(user).to receive(:oauth_identities).and_return(ar_collection)
        allow(ar_collection).to receive(:exists?).and_return(true)
      end

      it "uses exists? when available" do
        expect(ar_collection).to receive(:exists?)
        user.oauth_user?
      end
    end
  end
end
