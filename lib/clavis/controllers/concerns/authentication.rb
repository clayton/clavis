# frozen_string_literal: true

require "active_support/concern"

module Clavis
  module Controllers
    module Concerns
      module Authentication
        extend ActiveSupport::Concern

        def oauth_authorize
          provider_name = params[:provider]

          # Check if provider is specified
          if provider_name.blank?
            error_message = "No provider specified for OAuth authentication"
            Clavis::Logging.log_error(error_message)

            # Return a meaningful error to the user
            flash[:alert] = "Authentication provider not specified. Please try again or contact support."
            redirect_to main_app.respond_to?(:root_path) ? main_app.root_path : "/"
            return
          end

          begin
            # Explicitly validate provider - this will raise Clavis::ProviderNotConfigured if not configured
            Clavis.configuration.validate_provider!(provider_name)

            # Initialize the provider - if it fails, let the exception bubble up
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

            # Generate the authorization URL and redirect
            auth_url = provider.authorize_url(
              state: state,
              nonce: nonce,
              scope: scope
            )

            redirect_to auth_url, allow_other_host: true
          rescue StandardError => e
            # Only rescue non-configuration errors
            raise if e.is_a?(Clavis::ProviderNotConfigured) || e.is_a?(Clavis::ConfigurationError)

            # Re-raise configuration errors to make them visible

            Clavis::Logging.log_error("OAuth flow error: #{e.class.name} - #{e.message}")
            Clavis::Logging.log_error(e.backtrace.join("\n"))

            flash[:alert] = "An error occurred while setting up authentication. Please try again or contact support."
            redirect_to main_app.respond_to?(:root_path) ? main_app.root_path : "/"
          end
        end

        def oauth_callback
          provider_name = params[:provider].to_sym
          Clavis::Logging.debug("oauth_callback - Starting for provider: #{provider_name}")

          # Debug log of all params
          oauth_params = request.env["action_dispatch.request.parameters"] || params.to_unsafe_h

          # Check if the OAuth provider returned an error
          return handle_oauth_error(oauth_params["error"]) if oauth_params["error"]

          # Verify state to prevent CSRF
          validate_state(oauth_params["state"])

          # Validate the code parameter
          validate_code(oauth_params["code"])

          # Create provider instance
          provider = Clavis.provider(provider_name)
          Clavis::Logging.debug("oauth_callback - Provider created: #{provider.class.name}")

          # Debug logging for token verification status
          log_token_verification_status(provider)

          # Process the OAuth callback
          auth_hash = process_provider_callback(provider, oauth_params)

          # Find or create user if configured
          user = find_or_create_user(auth_hash)

          # Security measures and session management
          handle_session_security(auth_hash)

          # Process ID token claims if OpenID Connect provider
          process_claims_if_needed(auth_hash)

          # Yield to a block if given - for custom logic
          yield(auth_hash, user) if block_given?

          Clavis::Logging.debug("oauth_callback - Completed successfully")
          auth_hash
        rescue StandardError => e
          Clavis::Logging.debug("oauth_callback - Error: #{e.class.name}: #{e.message}")
          Clavis::Logging.debug("oauth_callback - Backtrace: #{e.backtrace.join("\n")}")
          handle_auth_error(e)
        end

        private

        def valid_state_token?(state)
          Clavis::Security::SessionManager.valid_state?(session, state, clear_after_validation: true)
        end

        def retrieve_nonce(clear: false)
          Clavis::Security::SessionManager.retrieve_nonce(session, clear_after_retrieval: clear)
        end

        def handle_auth_error(error)
          case error
          when Clavis::AuthorizationDenied
            raise error
          when Clavis::InvalidState, Clavis::MissingState, Clavis::ExpiredState,
               Clavis::InvalidNonce, Clavis::MissingNonce, Clavis::InvalidRedirectUri,
               Clavis::InvalidToken, Clavis::ExpiredToken, Clavis::InvalidGrant,
               Clavis::InvalidHostedDomain
            # All these errors get wrapped in a common AuthenticationError
            raise Clavis::AuthenticationError, "Authentication failed: #{error.message}"
          else
            # All other errors get a generic error message
            raise Clavis::AuthenticationError, "Authentication error: #{error.message}"
          end
        end

        def handle_oauth_error(error, description = nil)
          # Sanitize error parameters
          error = Clavis::Security::InputValidator.sanitize(error)
          description = Clavis::Security::InputValidator.sanitize(description) if description

          case error
          when "access_denied"
            raise Clavis::AuthorizationDenied, description
          when "invalid_request", "unauthorized_client",
               "unsupported_response_type", "invalid_scope",
               "server_error", "temporarily_unavailable"
            raise Clavis::AuthenticationError, description || error
          else
            raise Clavis::AuthenticationError, description || "Unknown error: #{error}"
          end
        end

        def validate_state(state_param)
          Clavis::Logging.debug("oauth_callback - Verifying state parameter")

          # Skip state validation in test environments if flagged
          skip_state_validation = defined?(ENV.fetch("RAILS_ENV", nil)) &&
                                  ENV["RAILS_ENV"] == "test" &&
                                  respond_to?(:skip_state_validation?) &&
                                  skip_state_validation?

          # Validate state token if state validation is not skipped
          state_validation_skipped = ENV["CLAVIS_SKIP_STATE_VALIDATION"] == "true" || skip_state_validation

          if !state_validation_skipped && !valid_state_token?(state_param)
            Clavis::Logging.debug("oauth_callback - Invalid state parameter")
            raise Clavis::InvalidState
          end

          Clavis::Logging.debug("oauth_callback - State verification successful")
        end

        def validate_code(code_param)
          Clavis::Logging.debug("oauth_callback - Validating code parameter")

          # Skip code validation in test environments if flagged
          skip_code_validation = defined?(ENV.fetch("RAILS_ENV", nil)) &&
                                 ENV["RAILS_ENV"] == "test" &&
                                 respond_to?(:skip_code_validation?) &&
                                 skip_code_validation?

          # Validate code if code validation is not skipped
          code_validation_skipped = ENV["CLAVIS_SKIP_CODE_VALIDATION"] == "true" || skip_code_validation

          if !code_validation_skipped && !Clavis::Security::InputValidator.valid_code?(code_param)
            Clavis::Logging.debug("oauth_callback - Invalid code parameter")
            raise Clavis::InvalidGrant, "Invalid authorization code format"
          end

          Clavis::Logging.debug("oauth_callback - Code validation successful")
        end

        def log_token_verification_status(provider)
          token_verification = provider.instance_variable_get(:@token_verification_enabled)
          Clavis::Logging.debug("oauth_callback - Token verification enabled: #{token_verification}")
        end

        def process_provider_callback(provider, oauth_params)
          # Retrieve nonce for OpenID providers to verify ID tokens
          if provider.respond_to?(:openid_provider?) && provider.openid_provider?
            nonce = retrieve_nonce(clear: true)
            Clavis::Logging.debug("oauth_callback - Nonce retrieved from session: #{!nonce.nil?}")
          end

          # Handle Apple-specific parameters
          user_data = extract_apple_user_data(provider.provider_name, oauth_params)

          # Process the OAuth callback
          Clavis::Logging.debug("oauth_callback - About to process callback with code")
          auth_hash = if provider.provider_name == :apple && user_data
                        Clavis::Logging.debug("oauth_callback - Processing Apple callback with user data")
                        provider.process_callback(oauth_params["code"], user_data)
                      else
                        Clavis::Logging.debug("oauth_callback - Processing callback with code only")
                        provider.process_callback(oauth_params["code"])
                      end

          Clavis::Logging.debug("oauth_callback - Callback processed successfully")
          Clavis::Logging.debug("oauth_callback - Auth hash: #{auth_hash.inspect}")

          auth_hash
        end

        def extract_apple_user_data(provider_name, oauth_params)
          return nil unless provider_name == :apple && oauth_params["user"].present?

          Clavis::Logging.debug("oauth_callback - Apple provider with user data")
          begin
            JSON.parse(oauth_params["user"])
          rescue JSON::ParserError
            nil
          end
        end

        def find_or_create_user(auth_hash)
          # Hook for find or create user by OAuth identity
          user = nil
          # Check if we should process the user from the auth hash
          has_user_processor = respond_to?(:find_or_create_user_from_auth) ||
                               self.class.private_method_defined?(:find_or_create_user_from_auth)

          if has_user_processor
            Clavis::Logging.debug("oauth_callback - User class: #{user_class}, finder method: #{finder_method}")
            begin
              user = find_or_create_user_from_auth(auth_hash)
            rescue NoMethodError => e
              Clavis::Logging.debug("oauth_callback - Missing finder method: #{finder_method}")
              raise Clavis::AuthenticationError, "Missing finder method: #{e.message}"
            end
          end

          # Process auth hash and store user identity if configured
          if user.respond_to?(:process_oauth_hash)
            Clavis::Logging.debug("oauth_callback - Finding or creating user")
            user.process_oauth_hash(auth_hash)
            Clavis::Logging.debug("oauth_callback - User found/created: #{user.inspect}")
          end

          user
        end

        def handle_session_security(auth_hash)
          # Rotate the session to prevent session fixation attacks
          rotate_session_if_configured

          # Store auth info in the session for use in the callback
          Clavis::Logging.debug("oauth_callback - Storing auth info in session")
          Clavis::Security::SessionManager.store_auth_info(session, auth_hash)
        end

        def rotate_session_if_configured
          return unless Clavis.configuration.rotate_session_after_login

          Clavis::Logging.debug("oauth_callback - Rotating session")
          # Skip session rotation in tests unless request object has been properly mocked
          skip_session_rotation = defined?(ENV.fetch("RAILS_ENV", nil)) &&
                                  ENV["RAILS_ENV"] == "test" &&
                                  (!request.respond_to?(:session) || !request.session.respond_to?(:keys))

          Clavis::Security::SessionManager.rotate_session(request) unless skip_session_rotation
        end

        def process_claims_if_needed(auth_hash)
          return unless auth_hash[:id_token_claims] && respond_to?(:process_id_token_claims)

          Clavis::Logging.debug("oauth_callback - Calling claims processor")
          process_id_token_claims(auth_hash[:id_token_claims], auth_hash)
        end
      end
    end
  end
end
