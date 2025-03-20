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

    it "allows configuring the token length" do
      # Generate state with custom length
      short_state = Clavis::Security::CsrfProtection.generate_state(8)
      long_state = Clavis::Security::CsrfProtection.generate_state(32)

      # Assertions
      expect(short_state.length).to eq(16) # 8 bytes = 16 hex chars
      expect(long_state.length).to eq(64) # 32 bytes = 64 hex chars
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

    it "stores state with expiration when provided" do
      freeze_time = Time.now
      allow(Time).to receive(:now).and_return(freeze_time)

      # Test state storage with expiration (10 minute expiry)
      expiry = 600
      state = Clavis::Security::CsrfProtection.store_state_in_session(mock_controller, expiry)

      # Assertions
      expect(mock_session[:oauth_state]).to eq(state)
      expect(mock_session[:oauth_state_expiry]).to eq(freeze_time.to_i + 600)
    end

    it "stores state with Time object expiration" do
      freeze_time = Time.now
      expiry_time = freeze_time + 600

      # Test state storage with Time expiration
      state = Clavis::Security::CsrfProtection.store_state_in_session(mock_controller, expiry_time)

      # Assertions
      expect(mock_session[:oauth_state]).to eq(state)
      expect(mock_session[:oauth_state_expiry]).to eq(expiry_time.to_i)
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

    it "raises an error when state has expired" do
      freeze_time = Time.now
      allow(Time).to receive(:now).and_return(freeze_time)

      # Store state with 10 minute expiration
      state = Clavis::Security::CsrfProtection.store_state_in_session(mock_controller, 600)

      # Move time forward 11 minutes
      allow(Time).to receive(:now).and_return(freeze_time + 660)

      # Test validation with expired state
      expect do
        Clavis::Security::CsrfProtection.validate_state_from_session!(mock_controller, state)
      end.to raise_error(Clavis::ExpiredState)
    end

    it "clears expired state from session" do
      freeze_time = Time.now
      allow(Time).to receive(:now).and_return(freeze_time)

      # Store state with 10 minute expiration
      Clavis::Security::CsrfProtection.store_state_in_session(mock_controller, 600)

      # Move time forward 11 minutes
      allow(Time).to receive(:now).and_return(freeze_time + 660)

      # Validation should fail but clear the session
      expect do
        Clavis::Security::CsrfProtection.validate_state_from_session!(mock_controller, "any-state")
      end.to raise_error(Clavis::ExpiredState)

      # Session should be cleared
      expect(mock_session[:oauth_state]).to be_nil
      expect(mock_session[:oauth_state_expiry]).to be_nil
    end

    it "clears state from session after validation" do
      # Store state in session
      state = Clavis::Security::CsrfProtection.store_state_in_session(mock_controller)

      # Validate state
      Clavis::Security::CsrfProtection.validate_state_from_session!(mock_controller, state)

      # Assertions
      expect(mock_session[:oauth_state]).to be_nil
    end

    it "clears state expiry from session after validation" do
      # Store state in session with expiration
      state = Clavis::Security::CsrfProtection.store_state_in_session(mock_controller, 600)

      # Validate state
      Clavis::Security::CsrfProtection.validate_state_from_session!(mock_controller, state)

      # Assertions
      expect(mock_session[:oauth_state]).to be_nil
      expect(mock_session[:oauth_state_expiry]).to be_nil
    end
  end

  describe "nonce handling with expiration" do
    let(:mock_session) { {} }
    let(:mock_controller) do
      double("Controller").tap do |controller|
        allow(controller).to receive(:session).and_return(mock_session)
      end
    end

    it "stores nonce with expiration when provided" do
      freeze_time = Time.now
      allow(Time).to receive(:now).and_return(freeze_time)

      # Test nonce storage with expiration (10 minute expiry)
      expiry = 600
      nonce = Clavis::Security::CsrfProtection.store_nonce_in_session(mock_controller, expiry)

      # Assertions
      expect(mock_session[:oauth_nonce]).to eq(nonce)
      expect(mock_session[:oauth_nonce_expiry]).to eq(freeze_time.to_i + 600)
    end

    it "raises an error when nonce has expired" do
      freeze_time = Time.now
      allow(Time).to receive(:now).and_return(freeze_time)

      # Store nonce with 10 minute expiration
      nonce = Clavis::Security::CsrfProtection.store_nonce_in_session(mock_controller, 600)

      # Move time forward 11 minutes
      allow(Time).to receive(:now).and_return(freeze_time + 660)

      # Test validation with expired nonce
      expect do
        Clavis::Security::CsrfProtection.validate_nonce_from_session!(mock_controller, nonce)
      end.to raise_error(Clavis::ExpiredState)
    end

    it "clears expired nonce from session" do
      freeze_time = Time.now
      allow(Time).to receive(:now).and_return(freeze_time)

      # Store nonce with 10 minute expiration
      Clavis::Security::CsrfProtection.store_nonce_in_session(mock_controller, 600)

      # Move time forward 11 minutes
      allow(Time).to receive(:now).and_return(freeze_time + 660)

      # Validation should fail but clear the session
      expect do
        Clavis::Security::CsrfProtection.validate_nonce_from_session!(mock_controller, "any-nonce")
      end.to raise_error(Clavis::ExpiredState)

      # Session should be cleared
      expect(mock_session[:oauth_nonce]).to be_nil
      expect(mock_session[:oauth_nonce_expiry]).to be_nil
    end
  end

  describe "session binding" do
    let(:session_id) { "session-id-123" }
    let(:state) { "test-state" } # Test with a state containing a hyphen

    before do
      # Mock the implementation to use a specific delimiter
      stub_const("Clavis::Security::CsrfProtection::STATE_HMAC_DELIMITER", "::")
    end

    context "simple bind and validate test" do
      let(:mock_session) { double("Session", id: session_id) }
      let(:mock_request) { double("Request", session: mock_session) }
      let(:mock_controller) do
        double("Controller", request: mock_request)
      end

      it "validates a simple bound state" do
        # Let's get really basic to debug the test
        hmac = OpenSSL::HMAC.hexdigest("SHA256", session_id, state)
        bound_state = "#{state}::#{hmac}"

        # The session ID should not have changed between bind and validate
        expect(mock_controller.request.session.id).to eq(session_id)

        # Should validate successfully
        result = Clavis::Security::CsrfProtection.validate_bound_state(mock_controller, bound_state)
        expect(result).to eq(state)
      end
    end

    context "standard tests" do
      let(:mock_session) { double("Session", id: session_id) }
      let(:mock_request) { double("Request", session: mock_session) }
      let(:mock_controller) do
        double("Controller", request: mock_request)
      end

      it "binds state to session" do
        bound_state = Clavis::Security::CsrfProtection.bind_state_to_session(mock_controller, state)

        # Should be in format "state::hmac"
        expect(bound_state).to include("#{state}::")
        expect(bound_state.split("::").length).to eq(2)
      end

      it "validates bound state properly" do
        # Use the actual implementation to generate the bound state
        bound_state = Clavis::Security::CsrfProtection.bind_state_to_session(mock_controller, state)

        # The session ID should not have changed between bind and validate
        expect(mock_controller.request.session.id).to eq(session_id)

        # Should validate successfully
        result = Clavis::Security::CsrfProtection.validate_bound_state(mock_controller, bound_state)
        expect(result).to eq(state)
      end

      it "rejects tampered bound state" do
        bound_state = Clavis::Security::CsrfProtection.bind_state_to_session(mock_controller, state)

        # Tamper with the state
        parts = bound_state.split("::")
        tampered_state = "evil-state::#{parts[1]}"

        # Should reject tampered state
        expect do
          Clavis::Security::CsrfProtection.validate_bound_state(mock_controller, tampered_state)
        end.to raise_error(Clavis::InvalidState)
      end

      it "rejects bound state with missing parts" do
        # Missing delimiter and HMAC
        expect do
          Clavis::Security::CsrfProtection.validate_bound_state(mock_controller, "just-state")
        end.to raise_error(Clavis::InvalidState)

        # Nil state
        expect do
          Clavis::Security::CsrfProtection.validate_bound_state(mock_controller, nil)
        end.to raise_error(Clavis::InvalidState)
      end

      it "rejects bound state from different session" do
        bound_state = Clavis::Security::CsrfProtection.bind_state_to_session(mock_controller, state)

        # Create a new controller with different session ID
        new_session = double("NewSession", id: "different-session-id")
        new_request = double("NewRequest", session: new_session)
        new_controller = double("NewController", request: new_request)

        # Should reject state from different session
        expect do
          Clavis::Security::CsrfProtection.validate_bound_state(new_controller, bound_state)
        end.to raise_error(Clavis::InvalidState)
      end
    end
  end
end
