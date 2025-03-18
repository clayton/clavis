# frozen_string_literal: true

require "spec_helper"
require "active_support/core_ext/object/blank"
require "active_support/time"

RSpec.describe "Clavis::OauthIdentity" do
  let(:user) { double("User", id: 1) }
  let(:future_time) { Time.now + 3600 } # 1 hour from now
  let(:future_timestamp) { future_time.to_i }

  # Use our already defined OauthIdentity mock from mocks/oauth_identity.rb
  let(:identity) do
    Clavis::OauthIdentity.new(
      provider: "google",
      uid: "123456",
      token: "access-token",
      refresh_token: "refresh-token",
      expires_at: future_time
    )
  end

  describe "#token_expired?" do
    context "when token is not expired" do
      it "returns false" do
        expect(identity.token_expired?).to be false
      end
    end

    context "when token is expired" do
      before do
        identity.expires_at = Time.now - 3600  # 1 hour ago
      end

      it "returns true" do
        expect(identity.token_expired?).to be true
      end
    end
  end

  describe "#token_valid?" do
    context "when token is present and not expired" do
      it "returns true" do
        expect(identity.token_valid?).to be true
      end
    end

    context "when token is expired" do
      before do
        identity.expires_at = Time.now - 3600  # 1 hour ago
      end

      it "returns false" do
        expect(identity.token_valid?).to be false
      end
    end
  end

  describe "#ensure_fresh_token" do
    let(:provider_instance) { double("Provider") }
    let(:new_tokens) do
      {
        access_token: "new-access-token",
        refresh_token: "new-refresh-token",
        expires_at: future_timestamp + 3600 # 2 hours from now
      }
    end
    let(:new_future_time) { Time.at(future_timestamp + 3600) }

    before do
      allow(Clavis).to receive(:provider).and_return(provider_instance)
      allow(provider_instance).to receive(:refresh_token).and_return(new_tokens)
      allow(Clavis).to receive_message_chain(:configuration, :providers, :dig).and_return("https://example.com/callback")

      # Mock Clavis::Logging instead of Rails.logger
      allow(Clavis::Logging).to receive(:log_token_refresh)
      allow(Clavis::Logging).to receive(:log_error)
    end

    context "when token is not expired" do
      it "returns the current token" do
        expect(identity.ensure_fresh_token).to eq("access-token")
      end
    end

    context "when token is expired but refresh token is present" do
      before do
        identity.expires_at = Time.now - 3600  # 1 hour ago
        allow(Time).to receive(:at).and_return(new_future_time)
      end

      it "refreshes the token" do
        result = identity.ensure_fresh_token

        expect(result).to eq("new-access-token")
        expect(identity.token).to eq("new-access-token")
        expect(identity.refresh_token).to eq("new-refresh-token")
        expect(identity.expires_at).to eq(new_future_time)
      end
    end

    context "when provider does not support refresh tokens" do
      before do
        identity.expires_at = Time.now - 3600  # 1 hour ago
        error = Clavis::UnsupportedOperation.new("Not supported by this provider")
        allow(provider_instance).to receive(:refresh_token).and_raise(error)
      end

      it "logs the error and returns the current token" do
        expect(identity.ensure_fresh_token).to eq("access-token")
        expect(Clavis::Logging).to have_received(:log_token_refresh).with("google", false, "Unsupported operation: Not supported by this provider")
      end
    end

    context "when refresh token fails" do
      before do
        identity.expires_at = Time.now - 3600  # 1 hour ago
        allow(provider_instance).to receive(:refresh_token).and_raise(Clavis::TokenError.new("Invalid token"))
      end

      it "logs the error and returns nil" do
        expect(identity.ensure_fresh_token).to be_nil
        expect(Clavis::Logging).to have_received(:log_error)
      end
    end
  end

  describe "#store_standardized_user_info!" do
    before do
      allow(Clavis::UserInfoNormalizer).to receive(:normalize).and_return({
                                                                            email: "normalized@example.com",
                                                                            name: "Normalized Name",
                                                                            avatar_url: "https://example.com/normalized-avatar.jpg"
                                                                          })
    end

    it "adds standardized info to auth_data" do
      identity.auth_data = { "email" => "original@example.com" }
      identity.store_standardized_user_info!

      expect(identity.auth_data["standardized"]).to be_a(Hash)
      expect(identity.auth_data["standardized"][:email]).to eq("normalized@example.com")
      expect(identity.auth_data["standardized"][:name]).to eq("Normalized Name")
      expect(identity.auth_data["standardized"][:avatar_url]).to eq("https://example.com/normalized-avatar.jpg")
    end

    it "preserves existing auth_data" do
      identity.auth_data = { "email" => "original@example.com", "custom_field" => "value" }
      identity.store_standardized_user_info!

      expect(identity.auth_data["email"]).to eq("original@example.com")
      expect(identity.auth_data["custom_field"]).to eq("value")
    end

    it "does nothing if auth_data is nil" do
      identity.auth_data = nil
      identity.store_standardized_user_info!

      expect(identity.auth_data).to be_nil
    end
  end
end
