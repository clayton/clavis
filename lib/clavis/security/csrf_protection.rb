# frozen_string_literal: true

require "securerandom"

module Clavis
  module Security
    module CsrfProtection
      class << self
        # Generates a secure random state token for CSRF protection
        # @return [String] A secure random state token
        def generate_state
          SecureRandom.hex(24)
        end

        # Validates that the actual state matches the expected state
        # @param actual_state [String] The state received from the OAuth provider
        # @param expected_state [String] The state that was originally sent
        # @raise [Clavis::MissingState] If either state is nil
        # @raise [Clavis::InvalidState] If the states don't match
        def validate_state!(actual_state, expected_state)
          raise Clavis::MissingState if actual_state.nil? || expected_state.nil?
          raise Clavis::InvalidState unless actual_state == expected_state
        end

        # Stores a state token in the Rails session
        # @param controller [ActionController::Base] The controller instance
        # @return [String] The generated state token
        def store_state_in_session(controller)
          state = generate_state
          controller.session[:oauth_state] = state
          state
        end

        # Validates the state from the Rails session
        # @param controller [ActionController::Base] The controller instance
        # @param actual_state [String] The state received from the OAuth provider
        # @raise [Clavis::MissingState] If either state is nil
        # @raise [Clavis::InvalidState] If the states don't match
        def validate_state_from_session!(controller, actual_state)
          expected_state = controller.session[:oauth_state]
          validate_state!(actual_state, expected_state)

          # Clear the state from the session after validation
          controller.session.delete(:oauth_state)
        end

        # Generates a nonce for OIDC requests
        # @return [String] A secure random nonce
        def generate_nonce
          SecureRandom.hex(16)
        end

        # Stores a nonce in the Rails session
        # @param controller [ActionController::Base] The controller instance
        # @return [String] The generated nonce
        def store_nonce_in_session(controller)
          nonce = generate_nonce
          controller.session[:oauth_nonce] = nonce
          nonce
        end

        # Validates the nonce from the ID token against the one in the session
        # @param controller [ActionController::Base] The controller instance
        # @param id_token_nonce [String] The nonce from the ID token
        # @raise [Clavis::MissingNonce] If either nonce is nil
        # @raise [Clavis::InvalidNonce] If the nonces don't match
        def validate_nonce_from_session!(controller, id_token_nonce)
          expected_nonce = controller.session[:oauth_nonce]

          raise Clavis::MissingNonce if id_token_nonce.nil? || expected_nonce.nil?
          raise Clavis::InvalidNonce unless id_token_nonce == expected_nonce

          # Clear the nonce from the session after validation
          controller.session.delete(:oauth_nonce)
        end
      end
    end
  end
end
