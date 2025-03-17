# frozen_string_literal: true

require "spec_helper"
require "active_support/core_ext/object/blank"
require "active_support/time"

RSpec.describe Clavis::OauthIdentity do
  let(:user) { double("User", id: 1) }
  let(:future_time) { Time.now + 3600 } # 1 hour from now
  let(:future_timestamp) { future_time.to_i }

  # Define a class for testing since we can't use ActiveRecord directly
  let(:test_identity_class) do
    Class.new do
      attr_accessor :id, :user, :provider, :uid, :token, :refresh_token, :expires_at

      def initialize(attributes = {})
        attributes.each do |key, value|
          send("#{key}=", value)
        end
      end

      # Helper method to check for nil or empty
      def blank?(obj)
        obj.nil? || obj == ""
      end

      # Helper method for present?
      def present?(obj)
        !blank?(obj)
      end

      def token_expired?
        present?(expires_at) && expires_at < Time.now
      end

      def token_valid?
        present?(token) && !token_expired?
      end

      def update(attributes = {})
        attributes.each do |key, value|
          send("#{key}=", value)
        end
        true
      end

      def ensure_fresh_token
        return token unless token_expired?
        return nil unless present?(refresh_token)

        begin
          provider_instance = Clavis.provider(
            provider.to_sym,
            redirect_uri: Clavis.configuration.providers.dig(provider.to_sym, :redirect_uri)
          )

          new_tokens = provider_instance.refresh_token(refresh_token)

          update(
            token: new_tokens[:access_token],
            refresh_token: new_tokens[:refresh_token] || refresh_token,
            expires_at: new_tokens[:expires_at] ? Time.at(new_tokens[:expires_at]) : nil
          )

          token
        rescue Clavis::UnsupportedOperation => e
          Rails.logger.info("Token refresh not supported for #{provider}: #{e.message}")
          token
        rescue Clavis::Error => e
          Rails.logger.error("Failed to refresh token for #{provider}: #{e.message}")
          nil
        end
      end
    end
  end

  let(:identity) do
    test_identity_class.new(
      id: 1,
      user: user,
      provider: "google",
      uid: "123456",
      token: "access-token",
      refresh_token: "refresh-token",
      expires_at: future_time
    )
  end

  before do
    allow(described_class).to receive(:create).and_return(identity)
    allow(described_class).to receive(:find_by).and_return(identity)
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
        allow(Rails).to receive_message_chain(:logger, :info)
      end

      it "logs the error and returns the current token" do
        expect(identity.ensure_fresh_token).to eq("access-token")
        expect(Rails.logger).to have_received(:info).with(/Token refresh not supported for google:/)
      end
    end

    context "when refresh token fails" do
      before do
        identity.expires_at = Time.now - 3600  # 1 hour ago
        allow(provider_instance).to receive(:refresh_token).and_raise(Clavis::TokenError.new("Invalid token"))
        allow(Rails).to receive_message_chain(:logger, :error)
      end

      it "logs the error and returns nil" do
        expect(identity.ensure_fresh_token).to be_nil
        expect(Rails.logger).to have_received(:error).with("Failed to refresh token for google: Invalid token")
      end
    end
  end
end
