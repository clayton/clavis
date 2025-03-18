# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::UserInfoNormalizer do
  describe ".normalize" do
    it "returns empty hash for non-hash input" do
      expect(described_class.normalize(:google, nil)).to eq({})
      expect(described_class.normalize(:google, "string")).to eq({})
      expect(described_class.normalize(:google, [])).to eq({})
    end

    it "normalizes Google provider info" do
      google_info = {
        email: "user@example.com",
        name: "Test User",
        picture: "https://example.com/avatar.jpg"
      }

      result = described_class.normalize(:google, google_info)

      expect(result[:email]).to eq("user@example.com")
      expect(result[:name]).to eq("Test User")
      expect(result[:avatar_url]).to eq("https://example.com/avatar.jpg")
    end

    it "normalizes GitHub provider info" do
      github_info = {
        email: "user@example.com",
        name: "Test User",
        avatar_url: "https://github.com/avatar.jpg"
      }

      result = described_class.normalize(:github, github_info)

      expect(result[:email]).to eq("user@example.com")
      expect(result[:name]).to eq("Test User")
      expect(result[:avatar_url]).to eq("https://github.com/avatar.jpg")
    end

    it "normalizes Facebook provider info" do
      facebook_info = {
        email: "user@example.com",
        name: "Test User",
        picture: "https://facebook.com/avatar.jpg"
      }

      result = described_class.normalize(:facebook, facebook_info)

      expect(result[:email]).to eq("user@example.com")
      expect(result[:name]).to eq("Test User")
      expect(result[:avatar_url]).to eq("https://facebook.com/avatar.jpg")
    end

    it "normalizes Apple provider info with separate first/last name" do
      apple_info = {
        email: "user@example.com",
        first_name: "Test",
        last_name: "User",
        email_verified: "user@example.com"
      }

      result = described_class.normalize(:apple, apple_info)

      expect(result[:email]).to eq("user@example.com")
      expect(result[:name]).to eq("Test User")
      expect(result[:avatar_url]).to be_nil
    end

    it "works with string keys" do
      info_with_string_keys = {
        "email" => "user@example.com",
        "name" => "Test User",
        "picture" => "https://example.com/avatar.jpg"
      }

      result = described_class.normalize(:google, info_with_string_keys)

      expect(result[:email]).to eq("user@example.com")
      expect(result[:name]).to eq("Test User")
      expect(result[:avatar_url]).to eq("https://example.com/avatar.jpg")
    end

    it "handles missing fields gracefully" do
      incomplete_info = {
        email: "user@example.com"
      }

      result = described_class.normalize(:google, incomplete_info)

      expect(result[:email]).to eq("user@example.com")
      expect(result[:name]).to be_nil
      expect(result[:avatar_url]).to be_nil
    end
  end
end
