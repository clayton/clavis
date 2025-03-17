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

          # Validate redirect URI if provided
          if params[:redirect_uri].present?
            Clavis::Security::RedirectUriValidator.validate_uri!(params[:redirect_uri])
            # Store the validated redirect URI in the session for later use
            session[:oauth_redirect_uri] = params[:redirect_uri]
          end

          # Generate and store state and nonce in session
          state = Clavis::Security::CsrfProtection.store_state_in_session(self)
          nonce = Clavis::Security::CsrfProtection.store_nonce_in_session(self)

          # Log parameters safely
          Clavis::Security::ParameterFilter.log_parameters(
            { provider: provider_name, scope: params[:scope] },
            level: :info,
            message: "Starting OAuth flow"
          )

          redirect_to provider.authorize_url(
            state: state,
            nonce: nonce,
            scope: params[:scope] || Clavis.configuration.default_scopes
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
          Clavis::Security::CsrfProtection.validate_state_from_session!(self, params[:state])

          provider = Clavis.provider(provider_name)
          auth_hash = provider.process_callback(params[:code])

          # Verify nonce in ID token if present
          if auth_hash[:id_token_claims] && auth_hash[:id_token_claims][:nonce]
            Clavis::Security::CsrfProtection.validate_nonce_from_session!(
              self,
              auth_hash[:id_token_claims][:nonce]
            )
          end

          user = find_or_create_user_from_oauth(auth_hash)

          # Let the application handle the user authentication
          if block_given?
            yield(user, auth_hash)
          else
            # Default behavior: redirect to the stored redirect URI or root path
            redirect_uri = session.delete(:oauth_redirect_uri) || "/"

            # Validate the redirect URI again before redirecting
            Clavis::Security::RedirectUriValidator.validate_uri!(redirect_uri)

            redirect_to redirect_uri
          end
        end

        private

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
