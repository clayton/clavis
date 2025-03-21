# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::Logging do
  let(:logger) { double("Logger") }

  before do
    # Mock the logger
    allow(described_class).to receive(:logger).and_return(logger)
    allow(logger).to receive(:info)
    allow(logger).to receive(:error)
    allow(logger).to receive(:warn)

    # Reset configuration
    Clavis.reset_configuration!
  end

  describe ".verbose_logging?" do
    it "returns false when verbose_logging is not set" do
      expect(described_class.verbose_logging?).to eq(false)
    end

    it "returns true when verbose_logging is enabled" do
      Clavis.configure { |config| config.verbose_logging = true }
      expect(described_class.verbose_logging?).to eq(true)
    end

    it "returns false when verbose_logging is disabled" do
      Clavis.configure { |config| config.verbose_logging = false }
      expect(described_class.verbose_logging?).to eq(false)
    end
  end

  describe "authentication logs" do
    context "when verbose_logging is disabled" do
      before do
        Clavis.configure { |config| config.verbose_logging = false }
      end

      it "does not log token refresh" do
        described_class.log_token_refresh(:google, true)
        expect(logger).not_to have_received(:info)
      end

      it "does not log token exchange" do
        described_class.log_token_exchange(:google, true)
        expect(logger).not_to have_received(:info)
      end

      it "does not log userinfo request" do
        described_class.log_userinfo_request(:google, true)
        expect(logger).not_to have_received(:info)
      end

      it "does not log token verification" do
        described_class.log_token_verification(:google, true)
        expect(logger).not_to have_received(:info)
      end

      it "does not log custom operations" do
        described_class.log_custom("test_operation", true)
        expect(logger).not_to have_received(:info)
      end
    end

    context "when verbose_logging is enabled" do
      before do
        Clavis.configure { |config| config.verbose_logging = true }
      end

      it "logs token refresh" do
        described_class.log_token_refresh(:google, true)
        expect(logger).to have_received(:info).with("[Clavis] Token refresh for google: success")
      end

      it "logs token exchange" do
        described_class.log_token_exchange(:google, true)
        expect(logger).to have_received(:info).with("[Clavis] Token exchange for google: success")
      end

      it "logs userinfo request" do
        described_class.log_userinfo_request(:google, true)
        expect(logger).to have_received(:info).with("[Clavis] Userinfo request for google: success")
      end

      it "logs token verification" do
        described_class.log_token_verification(:google, true)
        expect(logger).to have_received(:info).with("[Clavis] Token verification for google: success")
      end

      it "logs custom operations" do
        described_class.log_custom("test_operation", true)
        expect(logger).to have_received(:info).with("[Clavis] test_operation: success")
      end
    end
  end

  describe "security warnings" do
    it "always logs security warnings regardless of verbose_logging setting" do
      Clavis.configure { |config| config.verbose_logging = false }
      described_class.security_warning("Test security warning")
      expect(logger).to have_received(:warn).with("[Clavis Security Warning] Test security warning")
    end
  end

  describe "error logging" do
    it "always logs errors regardless of verbose_logging setting" do
      Clavis.configure { |config| config.verbose_logging = false }
      described_class.log_error("Test error")
      expect(logger).to have_received(:error).with("[Clavis] Error: Test error")
    end
  end
end
