# frozen_string_literal: true

require "active_support/concern"

module Clavis
  module Controllers
    module Concerns
      module Authentication
        extend ActiveSupport::Concern

        def oauth_authorize
          Rails.logger.debug "CLAVIS DEBUG: Starting oauth_authorize method"
          provider_name = params[:provider]
          Rails.logger.debug "CLAVIS DEBUG: Provider name from params: #{provider_name.inspect}"

          # Check if provider is specified
          if provider_name.blank?
            Rails.logger.debug "CLAVIS DEBUG: Provider name is blank"
            error_message = "No provider specified for OAuth authentication"
            Clavis::Logging.log_error(error_message)
            Rails.logger.error "CLAVIS DEBUG: #{error_message}"

            # Return a meaningful error to the user
            flash[:alert] = "Authentication provider not specified. Please try again or contact support."
            redirect_to main_app.respond_to?(:root_path) ? main_app.root_path : "/"
            return
          end

          Rails.logger.debug "CLAVIS DEBUG: About to check if provider '#{provider_name}' is configured"
          Rails.logger.debug "CLAVIS DEBUG: Available providers in config: " \
                             "#{Clavis.configuration.providers.keys.inspect}"

          begin
            # Explicitly validate provider - this will raise Clavis::ProviderNotConfigured if not configured
            Rails.logger.debug "CLAVIS DEBUG: Calling validate_provider! for #{provider_name}"
            Clavis.configuration.validate_provider!(provider_name)
            Rails.logger.debug "CLAVIS DEBUG: Provider validated successfully"

            # Initialize the provider - if it fails, let the exception bubble up
            Rails.logger.debug "CLAVIS DEBUG: Initializing provider #{provider_name}"
            provider = Clavis.provider(provider_name)
            Rails.logger.debug "CLAVIS DEBUG: Provider initialized: #{provider.class.name}"

            # Validate and store redirect URI if provided
            if params[:redirect_uri].present?
              Rails.logger.debug "CLAVIS DEBUG: Storing redirect_uri: #{params[:redirect_uri]}"
              Clavis::Security::SessionManager.store_redirect_uri(session, params[:redirect_uri])
            end

            # Generate and store state and nonce in session
            Rails.logger.debug "CLAVIS DEBUG: Generating state and nonce"
            state = Clavis::Security::SessionManager.generate_and_store_state(session)
            nonce = Clavis::Security::SessionManager.generate_and_store_nonce(session)
            Rails.logger.debug "CLAVIS DEBUG: State generated: #{state[0..5]}... (truncated)"

            # Log parameters safely
            Rails.logger.debug "CLAVIS DEBUG: Logging parameters for OAuth flow"
            Clavis::Security::ParameterFilter.log_parameters(
              { provider: provider_name, scope: params[:scope] },
              level: :info,
              message: "Starting OAuth flow"
            )

            # Validate inputs
            scope = params[:scope] || Clavis.configuration.default_scopes
            Rails.logger.debug "CLAVIS DEBUG: Using scope: #{scope.inspect}"
            Clavis::Security::InputValidator.sanitize(scope)

            # Generate the authorization URL and redirect
            Rails.logger.debug "CLAVIS DEBUG: Generating authorization URL"
            auth_url = provider.authorize_url(
              state: state,
              nonce: nonce,
              scope: scope
            )

            Rails.logger.debug "CLAVIS DEBUG: Authorization URL generated: #{auth_url}"
            Rails.logger.debug "CLAVIS DEBUG: Redirecting to authorization URL"

            redirect_to auth_url, allow_other_host: true
            Rails.logger.debug "CLAVIS DEBUG: Redirect initiated"
          rescue StandardError => e
            Rails.logger.error "CLAVIS DEBUG: Error in oauth_authorize: #{e.class.name} - #{e.message}"
            Rails.logger.error "CLAVIS DEBUG: Backtrace: #{e.backtrace.join("\n")}"

            # Only rescue non-configuration errors
            if e.is_a?(Clavis::ProviderNotConfigured) || e.is_a?(Clavis::ConfigurationError)
              # Re-raise configuration errors to make them visible
              Rails.logger.error "CLAVIS DEBUG: Re-raising configuration error"
              raise
            else
              Clavis::Logging.log_error("OAuth flow error: #{e.class.name} - #{e.message}")
              Clavis::Logging.log_error(e.backtrace.join("\n"))

              flash[:alert] = "An error occurred while setting up authentication. Please try again or contact support."
              redirect_to main_app.respond_to?(:root_path) ? main_app.root_path : "/"
            end
          end
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

          begin
            # Exchange code for tokens
            auth_hash = provider.process_callback(params[:code])

            # Find or create the user using the configured class and method
            user_class = Clavis.configuration.user_class.constantize
            finder_method = Clavis.configuration.user_finder_method

            # Ensure the configured method exists
            unless user_class.respond_to?(finder_method)
              raise Clavis::ConfigurationError,
                    "The method '#{finder_method}' is not defined on the #{user_class.name} class. " \
                    "Please implement this method to handle user creation from OAuth, or " \
                    "configure a different user_finder_method in your Clavis configuration."
            end

            # Call the configured method to find or create the user
            user = user_class.public_send(finder_method, auth_hash)

            # Rotate session ID for security
            Clavis::Security::SessionManager.rotate_session(request) if Clavis.configuration.rotate_session_after_login

            # Store additional information in the session
            Clavis::Security::SessionManager.store_auth_info(session, auth_hash)

            # Invoke custom claims processor if configured
            if Clavis.configuration.claims_processor.respond_to?(:call)
              Clavis.configuration.claims_processor.call(auth_hash, user)
            end

            # Yield to block for custom processing
            yield(user, auth_hash) if block_given?
          rescue StandardError => e
            Rails.logger.error "Clavis: OAuth callback error: #{e.class.name} - #{e.message}" if defined?(Rails)
            Rails.logger.error "Backtrace: #{e.backtrace.join("\n")}" if defined?(Rails) && e.backtrace
            raise Clavis::AuthenticationError, e.message
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
          when "invalid_request", "unauthorized_client",
               "unsupported_response_type", "invalid_scope",
               "server_error", "temporarily_unavailable"
            raise Clavis::AuthenticationError, description || error
          else
            raise Clavis::AuthenticationError, description || "Unknown error: #{error}"
          end
        end

        def find_or_create_user_from_oauth(auth_hash)
          # If the User class has the find_for_oauth method, use it
          if defined?(User) && User.respond_to?(:find_for_oauth)
            User.find_for_oauth(auth_hash)
          # If there's a User class that includes OauthAuthenticatable, use the module's method
          elsif defined?(User) && User.include?(Clavis::Models::Concerns::OauthAuthenticatable)
            # Find or create the identity
            identity = Clavis::OauthIdentity.find_or_initialize_by(
              provider: auth_hash[:provider],
              uid: auth_hash[:uid]
            )

            user = if identity.user.present?
                     identity.user
                   elsif auth_hash.dig(:info, :email).present?
                     # Try to find user by email
                     user_email_field = User.new.respond_to?(:email) ? :email : :email_address
                     User.find_by(user_email_field => auth_hash.dig(:info, :email)) ||
                       begin
                         new_user = User.new
                         if new_user.respond_to?(user_email_field)
                           new_user.send(:"#{user_email_field}=", auth_hash.dig(:info, :email))
                         end

                         # Set password if applicable
                         if new_user.respond_to?(:password=) && new_user.respond_to?(:password_confirmation=)
                           password = SecureRandom.hex(16)
                           new_user.password = password
                           new_user.password_confirmation = password if new_user.respond_to?(:password_confirmation=)
                         end

                         # Set name if applicable
                         set_user_name_from_auth_hash(new_user, auth_hash) if auth_hash.dig(:info, :name).present?

                         new_user.save!
                         new_user
                       end
                   else
                     # No email found, create a new user without email
                     User.create!(password: SecureRandom.hex(16))
                   end

            # Update the identity with the latest auth data
            identity.user = user
            identity.auth_data = auth_hash[:info]
            identity.token = auth_hash.dig(:credentials, :token)
            identity.refresh_token = auth_hash.dig(:credentials, :refresh_token)
            identity.expires_at = if auth_hash.dig(:credentials, :expires_at)
                                    Time.at(auth_hash.dig(:credentials, :expires_at))
                                  end
            identity.store_standardized_user_info!
            identity.save!

            user
          else
            # No User class or not proper configuration, just return the auth hash
            auth_hash
          end
        end

        # Helper method to set user name from auth hash
        def set_user_name_from_auth_hash(user, auth_hash)
          return unless auth_hash.dig(:info, :name).present?

          name_parts = auth_hash.dig(:info, :name).split
          user.first_name = name_parts.first if user.respond_to?(:first_name=)

          return unless name_parts.size > 1 && user.respond_to?(:last_name=)

          user.last_name = name_parts.drop(1).join(" ")
        end
      end
    end
  end
end
