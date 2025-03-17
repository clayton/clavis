# frozen_string_literal: true

require "active_support/concern"

module Clavis
  module Controllers
    module Concerns
      module Authentication
        extend ActiveSupport::Concern

        def oauth_authorize
          provider = Clavis.provider(params[:provider])
          redirect_to provider.authorize_url(
            state: generate_state,
            nonce: generate_nonce,
            scope: params[:scope] || Clavis.configuration.default_scopes
          )
        end

        def oauth_callback
          # Check for error response from provider
          if params[:error].present?
            handle_oauth_error(params[:error], params[:error_description])
            return
          end

          # Verify state parameter to prevent CSRF
          validate_state!(params[:state])

          provider = Clavis.provider(params[:provider])
          auth_hash = provider.process_callback(params[:code], session.delete(:oauth_state))
          user = find_or_create_user_from_oauth(auth_hash)

          # Let the application handle the user authentication
          yield(user, auth_hash) if block_given?
        end

        private

        def generate_state
          state = Clavis::Utils::SecureToken.generate_state
          session[:oauth_state] = state
          state
        end

        def generate_nonce
          Clavis::Utils::SecureToken.generate_nonce
        end

        def validate_state!(state)
          expected_state = session[:oauth_state]

          raise Clavis::MissingState.new if expected_state.nil?

          return unless state != expected_state

          raise Clavis::InvalidState.new
        end

        def handle_oauth_error(error, description = nil)
          case error
          when "access_denied"
            raise Clavis::AuthorizationDenied.new(description)
          when "invalid_request", "unauthorized_client", "unsupported_response_type", "invalid_scope", "server_error", "temporarily_unavailable"
            raise Clavis::AuthenticationError.new(description || error)
          else
            raise Clavis::AuthenticationError.new(description || "Unknown error: #{error}")
          end
        end

        def find_or_create_user_from_oauth(auth_hash)
          # This should be implemented by the application
          # Default implementation just returns the auth hash
          auth_hash
        end
      end
    end
  end
end
