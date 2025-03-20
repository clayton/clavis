# frozen_string_literal: true

require "securerandom"

module Clavis
  module Security
    module CsrfProtection
      class << self
        # Delimiter used to separate state from HMAC
        STATE_HMAC_DELIMITER = "::"

        # Generates a secure random state token for CSRF protection
        # @param length [Integer] The byte length for the token (resulting hex string will be twice this length)
        # @return [String] A secure random state token
        def generate_state(length = 24)
          SecureRandom.hex(length)
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
        # @param expiry [Time, Integer] Optional expiration time (Time object or seconds from now)
        # @param length [Integer] Optional byte length for the token
        # @return [String] The generated state token
        def store_state_in_session(controller, expiry = nil, length = 24)
          state = generate_state(length)
          controller.session[:oauth_state] = state

          # Store expiration if provided
          if expiry
            expiry_time = expiry.is_a?(Integer) ? Time.now.to_i + expiry : expiry.to_i
            controller.session[:oauth_state_expiry] = expiry_time
          end

          state
        end

        # Validates the state from the Rails session
        # @param controller [ActionController::Base] The controller instance
        # @param actual_state [String] The state received from the OAuth provider
        # @raise [Clavis::MissingState] If either state is nil
        # @raise [Clavis::InvalidState] If the states don't match
        # @raise [Clavis::ExpiredState] If the state token has expired
        def validate_state_from_session!(controller, actual_state)
          expected_state = controller.session[:oauth_state]
          expiry = controller.session[:oauth_state_expiry]

          # Check for expiration if an expiry was set
          if expiry && Time.now.to_i > expiry
            # Clear expired state from session
            controller.session.delete(:oauth_state)
            controller.session.delete(:oauth_state_expiry)
            raise Clavis::ExpiredState
          end

          validate_state!(actual_state, expected_state)

          # Clear the state from the session after validation
          controller.session.delete(:oauth_state)
          controller.session.delete(:oauth_state_expiry)
        end

        # Generates a nonce for OIDC requests
        # @param length [Integer] The byte length for the nonce (resulting hex string will be twice this length)
        # @return [String] A secure random nonce
        def generate_nonce(length = 16)
          SecureRandom.hex(length)
        end

        # Stores a nonce in the Rails session
        # @param controller [ActionController::Base] The controller instance
        # @param expiry [Time, Integer] Optional expiration time (Time object or seconds from now)
        # @param length [Integer] Optional byte length for the nonce
        # @return [String] The generated nonce
        def store_nonce_in_session(controller, expiry = nil, length = 16)
          nonce = generate_nonce(length)
          controller.session[:oauth_nonce] = nonce

          # Store expiration if provided
          if expiry
            expiry_time = expiry.is_a?(Integer) ? Time.now.to_i + expiry : expiry.to_i
            controller.session[:oauth_nonce_expiry] = expiry_time
          end

          nonce
        end

        # Validates the nonce from the ID token against the one in the session
        # @param controller [ActionController::Base] The controller instance
        # @param id_token_nonce [String] The nonce from the ID token
        # @raise [Clavis::MissingNonce] If either nonce is nil
        # @raise [Clavis::InvalidNonce] If the nonces don't match
        # @raise [Clavis::ExpiredState] If the nonce has expired
        def validate_nonce_from_session!(controller, id_token_nonce)
          expected_nonce = controller.session[:oauth_nonce]
          expiry = controller.session[:oauth_nonce_expiry]

          # Check for expiration if an expiry was set
          if expiry && Time.now.to_i > expiry
            # Clear expired nonce from session
            controller.session.delete(:oauth_nonce)
            controller.session.delete(:oauth_nonce_expiry)
            raise Clavis::ExpiredState
          end

          raise Clavis::MissingNonce if id_token_nonce.nil? || expected_nonce.nil?
          raise Clavis::InvalidNonce unless id_token_nonce == expected_nonce

          # Clear the nonce from the session after validation
          controller.session.delete(:oauth_nonce)
          controller.session.delete(:oauth_nonce_expiry)
        end

        # Binds a state token to the session context for extra security
        # @param controller [ActionController::Base] The controller instance
        # @param state [String] The state token to bind
        # @return [String] The bound state token (state::hmac format)
        def bind_state_to_session(controller, state)
          session_id = controller.request.session.id
          hmac = OpenSSL::HMAC.hexdigest("SHA256", session_id, state)
          "#{state}#{STATE_HMAC_DELIMITER}#{hmac}"
        end

        # Validates a state token that was bound to the session
        # @param controller [ActionController::Base] The controller instance
        # @param bound_state [String] The bound state token (state::hmac format)
        # @return [String] The original state if valid
        # @raise [Clavis::InvalidState] If the state is invalid or HMAC doesn't match
        def validate_bound_state(controller, bound_state)
          # Split using the delimiter - allows state to contain hyphens
          parts = bound_state.to_s.split(STATE_HMAC_DELIMITER)

          # We expect exactly 2 parts: state and hmac
          raise Clavis::InvalidState if parts.length != 2

          state = parts[0]
          received_hmac = parts[1]

          # Basic validation
          raise Clavis::InvalidState if state.nil? || received_hmac.nil? || state.empty? || received_hmac.empty?

          # Verify HMAC
          session_id = controller.request.session.id
          expected_hmac = OpenSSL::HMAC.hexdigest("SHA256", session_id, state)

          raise Clavis::InvalidState unless received_hmac == expected_hmac

          # Return the original state if valid
          state
        end
      end
    end
  end
end
