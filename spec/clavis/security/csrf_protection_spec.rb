# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::CsrfProtection" do
  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "state generation" do
    it "generates a secure random state token" do
      # Test state generation
      state = Clavis::Security::CsrfProtection.generate_state

      # Assertions
      expect(state).to be_a(String)
      expect(state.length).to be >= 32 # Ensure it's sufficiently long
    end

    it "generates unique state tokens for each call" do
      # Generate multiple state tokens
      state1 = Clavis::Security::CsrfProtection.generate_state
      state2 = Clavis::Security::CsrfProtection.generate_state

      # Assertions
      expect(state1).not_to eq(state2)
    end
  end

  describe "state validation" do
    it "validates matching state tokens" do
      # Generate a state token
      state = Clavis::Security::CsrfProtection.generate_state

      # Test validation with matching tokens
      expect do
        Clavis::Security::CsrfProtection.validate_state!(state, state)
      end.not_to raise_error
    end

    it "raises an error for non-matching state tokens" do
      # Generate state tokens
      expected_state = Clavis::Security::CsrfProtection.generate_state
      actual_state = Clavis::Security::CsrfProtection.generate_state

      # Test validation with non-matching tokens
      expect do
        Clavis::Security::CsrfProtection.validate_state!(actual_state, expected_state)
      end.to raise_error(Clavis::InvalidState)
    end

    it "raises an error for missing state tokens" do
      # Test validation with nil state
      expect do
        Clavis::Security::CsrfProtection.validate_state!(nil, "expected_state")
      end.to raise_error(Clavis::MissingState)
    end

    it "raises an error for missing expected state" do
      # Test validation with nil expected state
      expect do
        Clavis::Security::CsrfProtection.validate_state!("actual_state", nil)
      end.to raise_error(Clavis::MissingState)
    end
  end

  describe "Rails integration" do
    let(:mock_session) { {} }
    let(:mock_controller) do
      double("Controller").tap do |controller|
        allow(controller).to receive(:session).and_return(mock_session)
      end
    end

    it "stores state in Rails session" do
      # Test state storage in Rails session
      state = Clavis::Security::CsrfProtection.store_state_in_session(mock_controller)

      # Assertions
      expect(state).to be_a(String)
      expect(mock_session[:oauth_state]).to eq(state)
    end

    it "validates state from Rails session" do
      # Store state in session
      state = Clavis::Security::CsrfProtection.store_state_in_session(mock_controller)

      # Test validation with state from session
      expect do
        Clavis::Security::CsrfProtection.validate_state_from_session!(mock_controller, state)
      end.not_to raise_error
    end

    it "raises an error for non-matching state in session" do
      # Store state in session
      Clavis::Security::CsrfProtection.store_state_in_session(mock_controller)

      # Test validation with different state
      expect do
        Clavis::Security::CsrfProtection.validate_state_from_session!(mock_controller, "different_state")
      end.to raise_error(Clavis::InvalidState)
    end

    it "clears state from session after validation" do
      # Store state in session
      state = Clavis::Security::CsrfProtection.store_state_in_session(mock_controller)

      # Validate state
      Clavis::Security::CsrfProtection.validate_state_from_session!(mock_controller, state)

      # Assertions
      expect(mock_session[:oauth_state]).to be_nil
    end
  end
end
