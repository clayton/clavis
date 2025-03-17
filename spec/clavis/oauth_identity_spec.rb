# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::OauthIdentity do
  let(:user) { double("User", id: 1) }
  let(:future_time) { Time.now + 3600 } # 1 hour from now
  let(:future_timestamp) { future_time.to_i }

  before do
    allow(described_class).to receive(:create).and_return(identity)
    allow(described_class).to receive(:find_by).and_return(identity)
  end

  let(:identity) do
    double(
      "OauthIdentity",
      id: 1,
      user: user,
      provider: "google",
      uid: "123456",
      token: "access-token",
      refresh_token: "refresh-token",
      expires_at: future_time,
      token_expired?: false,
      token_valid?: true,
      update: true,
      ensure_fresh_token: "access-token"
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
        allow(identity).to receive(:token_expired?).and_return(true)
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
        allow(identity).to receive(:token_valid?).and_return(false)
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
        allow(identity).to receive(:token_expired?).and_return(true)
        allow(identity).to receive(:ensure_fresh_token).and_call_original
        allow(Time).to receive(:at).and_return(new_future_time)
      end

      it "refreshes the token" do
        allow(identity).to receive(:token).and_return("new-access-token")
        allow(identity).to receive(:ensure_fresh_token).and_return("new-access-token")

        expect(identity.ensure_fresh_token).to eq("new-access-token")
        expect(identity).to have_received(:update).with(
          token: "new-access-token",
          refresh_token: "new-refresh-token",
          expires_at: new_future_time
        )
      end
    end

    context "when provider does not support refresh tokens" do
      before do
        allow(identity).to receive(:token_expired?).and_return(true)
        allow(identity).to receive(:ensure_fresh_token).and_call_original
        allow(provider_instance).to receive(:refresh_token).and_raise(Clavis::UnsupportedOperation.new("Not supported"))
        allow(Rails).to receive_message_chain(:logger, :info)
      end

      it "logs the error and returns the current token" do
        allow(identity).to receive(:ensure_fresh_token).and_return("access-token")
        expect(identity.ensure_fresh_token).to eq("access-token")
        expect(Rails.logger).to have_received(:info).with("Token refresh not supported for google: Not supported")
      end
    end

    context "when refresh token fails" do
      before do
        allow(identity).to receive(:token_expired?).and_return(true)
        allow(identity).to receive(:ensure_fresh_token).and_call_original
        allow(provider_instance).to receive(:refresh_token).and_raise(Clavis::TokenError.new("Invalid token"))
        allow(Rails).to receive_message_chain(:logger, :error)
      end

      it "logs the error and returns nil" do
        allow(identity).to receive(:ensure_fresh_token).and_return(nil)
        expect(identity.ensure_fresh_token).to be_nil
        expect(Rails.logger).to have_received(:error).with("Failed to refresh token for google: Invalid token")
      end
    end
  end
end
