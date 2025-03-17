# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::ParameterFilter" do
  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "parameter filtering" do
    it "filters sensitive parameters from logs" do
      # Setup
      Clavis.configure do |config|
        config.parameter_filter_enabled = true
      end

      # Create a mock parameters hash with sensitive data
      params = {
        code: "authorization_code_value",
        token: "access_token_value",
        refresh_token: "refresh_token_value",
        id_token: "id_token_value",
        client_secret: "client_secret_value",
        state: "state_value",
        nonce: "nonce_value",
        other_param: "non_sensitive_value"
      }

      # Test filtering
      filtered_params = Clavis::Security::ParameterFilter.filter_parameters(params)

      # Assertions
      expect(filtered_params[:code]).to eq("[FILTERED]")
      expect(filtered_params[:token]).to eq("[FILTERED]")
      expect(filtered_params[:refresh_token]).to eq("[FILTERED]")
      expect(filtered_params[:id_token]).to eq("[FILTERED]")
      expect(filtered_params[:client_secret]).to eq("[FILTERED]")
      expect(filtered_params[:state]).to eq("[FILTERED]")
      expect(filtered_params[:nonce]).to eq("[FILTERED]")
      expect(filtered_params[:other_param]).to eq("non_sensitive_value")
    end

    it "does not filter parameters when filtering is disabled" do
      # Setup
      Clavis.configure do |config|
        config.parameter_filter_enabled = false
      end

      # Create a mock parameters hash with sensitive data
      params = {
        code: "authorization_code_value",
        other_param: "non_sensitive_value"
      }

      # Test with filtering disabled
      filtered_params = Clavis::Security::ParameterFilter.filter_parameters(params)

      # Assertions
      expect(filtered_params[:code]).to eq("authorization_code_value")
      expect(filtered_params[:other_param]).to eq("non_sensitive_value")
    end
  end

  describe "Rails integration" do
    it "registers filter parameters with Rails when available" do
      # Mock Rails.application
      rails_app = double("Rails.application")
      allow(Rails).to receive(:application).and_return(rails_app)

      # Expect config.filter_parameters to be called with sensitive parameters
      expect(rails_app).to receive_message_chain(:config, :filter_parameters, :concat) do |params|
        expect(params).to include(:code, :token, :refresh_token, :id_token, :client_secret, :state, :nonce)
      end

      # Test Rails integration
      Clavis::Security::ParameterFilter.install_rails_filter
    end
  end
end
