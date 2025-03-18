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

      attr_accessor :id

      def initialize(id = 1)
        @id = id
        @oauth_identities = []
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
    # Explicitly set the auth_data to ensure it's property initialized
    identity.instance_variable_set(:@auth_data, {
                                     standardized: {
                                       email: "google@example.com",
                                       name: "Google User",
                                       avatar_url: "https://google.com/avatar.jpg"
                                     }
                                   })
    identity
  end

  let(:github_identity) do
    identity = Clavis::OauthIdentity.new
    identity.provider = "github"
    identity.updated_at = Time.now - 86_400 # 1 day in seconds
    # Explicitly set the auth_data to ensure it's property initialized
    identity.instance_variable_set(:@auth_data, {
                                     standardized: {
                                       email: "github@example.com",
                                       name: "GitHub User",
                                       avatar_url: "https://github.com/avatar.jpg"
                                     }
                                   })
    identity
  end

  describe "#oauth_avatar_url" do
    before do
      allow(user).to receive(:oauth_identities).and_return([google_identity, github_identity])
      allow(user).to receive(:oauth_identity_for).with("google").and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("github").and_return(github_identity)
    end

    it "returns avatar URL from most recent identity when no provider specified" do
      google_identity.updated_at = Time.now
      github_identity.updated_at = Time.now - 86_400 # 1 day in seconds

      expect(user.oauth_avatar_url).to eq("https://google.com/avatar.jpg")
    end

    it "returns avatar URL from specified provider when provider is given" do
      expect(user.oauth_avatar_url("github")).to eq("https://github.com/avatar.jpg")
    end

    it "returns nil when no identities exist" do
      allow(user).to receive(:oauth_identities).and_return([])

      expect(user.oauth_avatar_url).to be_nil
    end

    it "returns nil when identity has no standardized data" do
      identity_without_data = Clavis::OauthIdentity.new(
        provider: "empty",
        auth_data: {},
        updated_at: Time.now
      )

      allow(user).to receive(:oauth_identities).and_return([identity_without_data])

      expect(user.oauth_avatar_url).to be_nil
    end
  end

  describe "#oauth_name" do
    before do
      allow(user).to receive(:oauth_identities).and_return([google_identity, github_identity])
      allow(user).to receive(:oauth_identity_for).with("google").and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("github").and_return(github_identity)
    end

    it "returns name from most recent identity when no provider specified" do
      github_identity.updated_at = Time.now

      expect(user.oauth_name).to eq("GitHub User")
    end

    it "returns name from specified provider when provider is given" do
      expect(user.oauth_name("google")).to eq("Google User")
    end
  end

  describe "#oauth_email" do
    before do
      allow(user).to receive(:oauth_identities).and_return([google_identity, github_identity])
      allow(user).to receive(:oauth_identity_for).with("google").and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("github").and_return(github_identity)
    end

    it "returns email from most recent identity when no provider specified" do
      github_identity.updated_at = Time.now

      expect(user.oauth_email).to eq("github@example.com")
    end

    it "returns email from specified provider when provider is given" do
      expect(user.oauth_email("google")).to eq("google@example.com")
    end
  end

  describe "debugging" do
    it "inspects the identity objects in detail" do
      allow(user).to receive(:oauth_identities).and_return([google_identity, github_identity])
      allow(user).to receive(:oauth_identity_for).with("google").and_return(google_identity)
      allow(user).to receive(:oauth_identity_for).with("github").and_return(github_identity)

      # Test if the auth_data is working as expected
      expect(google_identity.auth_data).to include(:standardized)
      expect(google_identity.auth_data[:standardized]).to include(:email)
    end
  end

  describe "#oauth_user?" do
    context "when the user has OAuth identities" do
      before do
        allow(user).to receive(:oauth_identities).and_return([google_identity])
      end

      it "returns true" do
        expect(user.oauth_user?).to be true
      end
    end

    context "when the user has no OAuth identities" do
      before do
        allow(user).to receive(:oauth_identities).and_return([])
      end

      it "returns false" do
        expect(user.oauth_user?).to be false
      end
    end

    context "with ActiveRecord-like collection" do
      let(:ar_collection) { double("AR Collection") }

      before do
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
