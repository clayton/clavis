# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::SessionManager" do
  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "session storage" do
    it "stores and retrieves values from the session" do
      session = {}

      # Store a value
      Clavis::Security::SessionManager.store(session, :test_key, "test_value")

      # Retrieve the value
      expect(Clavis::Security::SessionManager.retrieve(session, :test_key)).to eq("test_value")
    end

    it "uses a namespaced key for storage" do
      session = {}

      # Store a value
      Clavis::Security::SessionManager.store(session, :test_key, "test_value")

      # Check that the value is stored with a namespaced key
      expect(session["clavis_test_key".to_sym]).to eq("test_value")
    end

    it "deletes values from the session" do
      session = {}

      # Store a value
      Clavis::Security::SessionManager.store(session, :test_key, "test_value")

      # Delete the value
      Clavis::Security::SessionManager.delete(session, :test_key)

      # Check that the value is deleted
      expect(Clavis::Security::SessionManager.retrieve(session, :test_key)).to be_nil
    end
  end

  describe "state management" do
    it "stores and validates state" do
      session = {}

      # Generate and store state
      state = Clavis::Security::SessionManager.generate_and_store_state(session)

      # Validate the state
      expect(Clavis::Security::SessionManager.valid_state?(session, state)).to be true

      # Validate an invalid state
      expect(Clavis::Security::SessionManager.valid_state?(session, "invalid_state")).to be false
    end

    it "clears state after validation" do
      session = {}

      # Generate and store state
      state = Clavis::Security::SessionManager.generate_and_store_state(session)

      # Validate the state
      Clavis::Security::SessionManager.valid_state?(session, state, clear_after_validation: true)

      # Check that the state is cleared
      expect(Clavis::Security::SessionManager.retrieve(session, :oauth_state)).to be_nil
    end
  end

  describe "nonce management" do
    it "stores and validates nonce" do
      session = {}

      # Generate and store nonce
      nonce = Clavis::Security::SessionManager.generate_and_store_nonce(session)

      # Validate the nonce
      expect(Clavis::Security::SessionManager.valid_nonce?(session, nonce)).to be true

      # Validate an invalid nonce
      expect(Clavis::Security::SessionManager.valid_nonce?(session, "invalid_nonce")).to be false
    end

    it "clears nonce after validation" do
      session = {}

      # Generate and store nonce
      nonce = Clavis::Security::SessionManager.generate_and_store_nonce(session)

      # Validate the nonce
      Clavis::Security::SessionManager.valid_nonce?(session, nonce, clear_after_validation: true)

      # Check that the nonce is cleared
      expect(Clavis::Security::SessionManager.retrieve(session, :oauth_nonce)).to be_nil
    end
  end

  describe "redirect URI management" do
    before do
      # Mock the RedirectUriValidator to avoid validation errors
      allow(Clavis::Security::RedirectUriValidator).to receive(:validate_uri!).and_return(true)
    end

    it "stores and retrieves redirect URI" do
      session = {}

      # Store a redirect URI
      Clavis::Security::SessionManager.store_redirect_uri(session, "/dashboard")

      # Retrieve the redirect URI
      expect(Clavis::Security::SessionManager.retrieve_redirect_uri(session)).to eq("/dashboard")
    end

    it "validates and retrieves redirect URI" do
      session = {}

      # Store a redirect URI
      Clavis::Security::SessionManager.store_redirect_uri(session, "/dashboard")

      # Validate and retrieve the redirect URI
      expect(Clavis::Security::SessionManager.validate_and_retrieve_redirect_uri(session)).to eq("/dashboard")

      # Check that the redirect URI is cleared
      expect(Clavis::Security::SessionManager.retrieve(session, :oauth_redirect_uri)).to be_nil
    end

    it "returns a default redirect URI if none is stored" do
      session = {}

      # Validate and retrieve the redirect URI with a default
      expect(Clavis::Security::SessionManager.validate_and_retrieve_redirect_uri(session,
                                                                                 default: "/home")).to eq("/home")
    end
  end

  describe "session security" do
    it "rotates session ID after authentication" do
      session = { id: "old_session_id" }

      # Simple mock that doesn't cause infinite recursion
      def session.clear
        # Do nothing
      end

      # Rotate session ID
      Clavis::Security::SessionManager.rotate_session_id(session, "new_session_id")

      # Check that the session ID was updated
      expect(session[:id]).to eq("new_session_id")
    end

    it "preserves specified keys during session rotation" do
      session = {
        id: "old_session_id",
        user_id: 123,
        some_other_key: "value"
      }

      # Simple mock that doesn't cause infinite recursion
      def session.clear
        delete(:some_other_key)
      end

      # Rotate session ID, preserving user_id
      Clavis::Security::SessionManager.rotate_session_id(session, "new_session_id", preserve_keys: [:user_id])

      # Check that user_id is preserved
      expect(session[:user_id]).to eq(123)

      # Check that other keys are not preserved
      expect(session[:some_other_key]).to be_nil

      # Check that the session ID was updated
      expect(session[:id]).to eq("new_session_id")
    end
  end
end
