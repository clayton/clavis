# frozen_string_literal: true

require "active_support/concern"

module Clavis
  module Controllers
    module Concerns
      module Authentication
        extend ActiveSupport::Concern

        def oauth_authorize
          provider_name = params[:provider]
          provider = Clavis.provider(provider_name)

          # Validate and store redirect URI if provided
          if params[:redirect_uri].present?
            Clavis::Security::SessionManager.store_redirect_uri(session, params[:redirect_uri])
          end

          # Generate and store state and nonce in session
          state = Clavis::Security::SessionManager.generate_and_store_state(session)
          nonce = Clavis::Security::SessionManager.generate_and_store_nonce(session)

          # Log parameters safely
          Clavis::Security::ParameterFilter.log_parameters(
            { provider: provider_name, scope: params[:scope] },
            level: :info,
            message: "Starting OAuth flow"
          )

          # Validate inputs
          scope = params[:scope] || Clavis.configuration.default_scopes
          Clavis::Security::InputValidator.sanitize(scope)

          redirect_to provider.authorize_url(
            state: state,
            nonce: nonce,
            scope: scope
          )
        end

        def oauth_callback
          provider_name = params[:provider]

          # Log parameters safely
          Clavis::Security::ParameterFilter.log_parameters(
            params.to_unsafe_h,
            level: :debug,
            message: "OAuth callback received"
          )

          # Check for error response from provider
          if params[:error].present?
            handle_oauth_error(params[:error], params[:error_description])
            return
          end

          # Verify state parameter to prevent CSRF
          unless Clavis::Security::SessionManager.valid_state?(session, params[:state], clear_after_validation: true)
            raise Clavis::InvalidState, "Invalid state parameter"
          end

          # Validate code parameter
          unless Clavis::Security::InputValidator.valid_code?(params[:code])
            raise Clavis::InvalidGrant, "Invalid authorization code"
          end

          provider = Clavis.provider(provider_name)
          auth_hash = provider.process_callback(params[:code])

          # Verify nonce in ID token if present
          if auth_hash[:id_token_claims] && auth_hash[:id_token_claims][:nonce] && !Clavis::Security::SessionManager.valid_nonce?(
            session,
            auth_hash[:id_token_claims][:nonce],
            clear_after_validation: true
          )
            raise Clavis::InvalidNonce, "Invalid nonce in ID token"
          end

          user = find_or_create_user_from_oauth(auth_hash)

          # Rotate session ID to prevent session fixation
          if defined?(request) && request.respond_to?(:session) && request.session.respond_to?(:id)
            new_session_id = SecureRandom.hex(32)
            Clavis::Security::SessionManager.rotate_session_id(
              session,
              new_session_id,
              preserve_keys: [:user_id]
            )
          end

          # Let the application handle the user authentication
          if block_given?
            yield(user, auth_hash)
          else
            # Default behavior: redirect to the stored redirect URI or root path
            redirect_uri = Clavis::Security::SessionManager.validate_and_retrieve_redirect_uri(
              session,
              default: "/"
            )

            redirect_to redirect_uri
          end
        end

        private

        def handle_oauth_error(error, description = nil)
          # Sanitize error parameters
          error = Clavis::Security::InputValidator.sanitize(error)
          description = Clavis::Security::InputValidator.sanitize(description) if description

          case error
          when "access_denied"
            raise Clavis::AuthorizationDenied, description
          when "invalid_request", "unauthorized_client", "unsupported_response_type", "invalid_scope", "server_error", "temporarily_unavailable"
            raise Clavis::AuthenticationError, description || error
          else
            raise Clavis::AuthenticationError, description || "Unknown error: #{error}"
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
