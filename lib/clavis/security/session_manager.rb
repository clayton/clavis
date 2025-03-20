# frozen_string_literal: true

require "securerandom"

module Clavis
  module Security
    module SessionManager
      class << self
        # Store a value in the session with a namespaced key
        # @param session [Hash] The session hash
        # @param key [Symbol] The key to store the value under
        # @param value [Object] The value to store
        def store(session, key, value)
          session[namespaced_key(key)] = value
        end

        # Retrieve a value from the session
        # @param session [Hash] The session hash
        # @param key [Symbol] The key to retrieve the value from
        # @return [Object, nil] The value or nil if not found
        def retrieve(session, key)
          session[namespaced_key(key)]
        end

        # Delete a value from the session
        # @param session [Hash] The session hash
        # @param key [Symbol] The key to delete
        # @return [Object, nil] The deleted value or nil if not found
        def delete(session, key)
          session.delete(namespaced_key(key))
        end

        # Generate a secure random state parameter and store it in the session
        # @param session [Hash] The session hash
        # @return [String] The generated state
        def generate_and_store_state(session)
          state = SecureRandom.hex(32)
          store(session, :oauth_state, state)
          state
        end

        # Check if a state parameter is valid
        # @param session [Hash] The session hash
        # @param state [String] The state parameter to validate
        # @param clear_after_validation [Boolean] Whether to clear the state after validation
        # @return [Boolean] Whether the state is valid
        def valid_state?(session, state, clear_after_validation: false)
          stored_state = retrieve(session, :oauth_state)

          # Clear the state if requested
          delete(session, :oauth_state) if clear_after_validation

          # Validate the state
          return false if stored_state.nil? || state.nil?

          # Validate the state format if input validation is enabled
          return false if Clavis.configuration.validate_inputs && !Clavis::Security::InputValidator.valid_state?(state)

          stored_state == state
        end

        # Generate a secure random nonce and store it in the session
        # @param session [Hash] The session hash
        # @return [String] The generated nonce
        def generate_and_store_nonce(session)
          nonce = SecureRandom.hex(32)
          store(session, :oauth_nonce, nonce)
          nonce
        end

        # Check if a nonce is valid
        # @param session [Hash] The session hash
        # @param nonce [String] The nonce to validate
        # @param clear_after_validation [Boolean] Whether to clear the nonce after validation
        # @return [Boolean] Whether the nonce is valid
        def valid_nonce?(session, nonce, clear_after_validation: false)
          stored_nonce = retrieve(session, :oauth_nonce)

          # Clear the nonce if requested
          delete(session, :oauth_nonce) if clear_after_validation

          # Validate the nonce
          return false if stored_nonce.nil? || nonce.nil?

          # Validate the nonce format if input validation is enabled
          return false if Clavis.configuration.validate_inputs && !Clavis::Security::InputValidator.valid_state?(nonce)

          stored_nonce == nonce
        end

        # Store a redirect URI in the session
        # @param session [Hash] The session hash
        # @param redirect_uri [String] The redirect URI to store
        def store_redirect_uri(session, redirect_uri)
          # Validate the redirect URI before storing
          return unless redirect_uri && !redirect_uri.empty?

          # Sanitize the redirect URI if input sanitization is enabled
          redirect_uri = Clavis::Security::InputValidator.sanitize(redirect_uri) if Clavis.configuration.sanitize_inputs

          Clavis::Security::RedirectUriValidator.validate_uri!(redirect_uri)
          store(session, :oauth_redirect_uri, redirect_uri)
        end

        # Retrieve a redirect URI from the session
        # @param session [Hash] The session hash
        # @return [String, nil] The redirect URI or nil if not found
        def retrieve_redirect_uri(session)
          retrieve(session, :oauth_redirect_uri)
        end

        # Validate and retrieve a redirect URI from the session
        # @param session [Hash] The session hash
        # @param default [String] The default redirect URI to use if none is stored
        # @return [String] The validated redirect URI or the default
        def validate_and_retrieve_redirect_uri(session, default: "/")
          redirect_uri = retrieve_redirect_uri(session)
          delete(session, :oauth_redirect_uri)

          if redirect_uri && !redirect_uri.empty?
            # Sanitize the redirect URI if input sanitization is enabled
            if Clavis.configuration.sanitize_inputs
              redirect_uri = Clavis::Security::InputValidator.sanitize(redirect_uri)
            end

            # Validate the redirect URI
            Clavis::Security::RedirectUriValidator.validate_uri!(redirect_uri)
            redirect_uri
          else
            default
          end
        end

        # Rotate the session ID after authentication
        # @param session [Hash] The session hash
        # @param new_session_id [String] The new session ID
        # @param preserve_keys [Array<Symbol>] Keys to preserve during rotation
        def rotate_session_id(session, new_session_id, preserve_keys: [])
          # Skip rotation if disabled in configuration
          return unless Clavis.configuration.rotate_session_after_login

          # Store values to preserve
          preserved_values = {}
          preserve_keys.each do |key|
            preserved_values[key] = session[key] if session.key?(key)
          end

          # Clear the session
          session.clear

          # Set the new session ID
          session[:id] = new_session_id

          # Restore preserved values
          preserved_values.each do |key, value|
            session[key] = value
          end
        end

        # Rotate session to improve security after login
        # @param request [ActionDispatch::Request] The current request
        def rotate_session(request)
          return unless Clavis.configuration.rotate_session_after_login
          return unless request.respond_to?(:session)

          if defined?(Rails) && Rails.version.to_f >= 6.0
            # For Rails 6.0+, use the built-in reset_session functionality
            # but preserve all session data
            old_session_data = {}

            # Copy all session data
            request.session.each do |key, value|
              old_session_data[key] = value
            end

            # Reset the session
            request.env["rack.session.options"][:renew] = true
            request.reset_session

            # Restore session data
            old_session_data.each do |key, value|
              request.session[key] = value
            end
          else
            # For older Rails versions or non-Rails apps, use our custom implementation
            keys_to_preserve = request.session.respond_to?(:keys) ? request.session.keys.map(&:to_sym) : []
            new_session_id = SecureRandom.hex(32)
            rotate_session_id(request.session, new_session_id, preserve_keys: keys_to_preserve)
          end
        end

        # Store authentication information in the session
        # @param session [Hash] The session hash
        # @param auth_hash [Hash] The authentication hash
        def store_auth_info(session, auth_hash)
          return unless auth_hash

          # Store minimal information in the session
          store(session, :provider, auth_hash[:provider])
          store(session, :uid, auth_hash[:uid])

          # Store email if available
          store(session, :email, auth_hash.dig(:info, :email)) if auth_hash.dig(:info, :email)

          # Store name if available
          store(session, :name, auth_hash.dig(:info, :name)) if auth_hash.dig(:info, :name)
        end

        private

        # Create a namespaced key for session storage
        # @param key [Symbol] The key to namespace
        # @return [Symbol] The namespaced key
        def namespaced_key(key)
          :"#{Clavis.configuration.session_key_prefix}_#{key}"
        end
      end
    end
  end
end
