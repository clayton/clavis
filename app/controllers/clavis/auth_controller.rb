# frozen_string_literal: true

module Clavis
  # AuthController directly inherits from ActionController::Base to avoid inheriting
  # host application's authentication requirements or before_actions that could
  # interfere with the OAuth flow
  class AuthController < ::ActionController::Base
    include Clavis::Controllers::Concerns::Authentication
    include Clavis::Controllers::Concerns::SessionManagement

    # Add basic controller setup
    protect_from_forgery with: :exception

    # Allow access to main_app routes
    helper Rails.application.routes.url_helpers if defined?(Rails)

    # Skip CSRF protection for OAuth callback endpoints since they come from external redirects
    skip_before_action :verify_authenticity_token, only: [:callback]

    def authorize
      # Store the current URL for returning after authentication
      store_location if request.get?

      oauth_authorize
    end

    def callback
      oauth_callback do |user, auth_hash|
        # This is a default implementation that can be overridden
        # by the application using the gem
        if respond_to?(:clavis_authentication_success)
          clavis_authentication_success(user, auth_hash)
        else
          # Use the SessionManagement method to sign in the user with secure cookies
          sign_in_user(user)

          # DEBUG: Log the redirect path
          redirect_path = after_login_path
          Rails.logger.debug "CLAVIS DEBUG: Redirecting after login to: #{redirect_path}"

          # Force redirect to root path if it's redirecting to auth path
          if redirect_path.include?("/auth/")
            Rails.logger.debug "CLAVIS DEBUG: Detected potential redirect loop to auth path. " \
                               "Redirecting to root instead."
            redirect_path = defined?(main_app) && main_app.respond_to?(:root_path) ? main_app.root_path : "/"
          end

          redirect_to redirect_path, notice: "Successfully signed in with #{params[:provider].capitalize}"
        end
      end
    rescue StandardError => e
      Clavis::Logging.log_error(e)

      if respond_to?(:clavis_authentication_failure)
        clavis_authentication_failure(e)
      else
        # Default behavior: redirect to sign in page with error
        flash[:alert] = case e
                        when Clavis::AuthorizationDenied
                          "Authentication was cancelled"
                        when Clavis::InvalidState, Clavis::MissingState
                          "Authentication session expired. Please try again."
                        else
                          "Authentication failed: #{e.message}"
                        end

        # Safe redirect to after_login_path
        redirect_to after_login_path
      end
    end

    private

    def find_or_create_user_from_oauth(auth_hash)
      user_class = Clavis.configuration.user_class.constantize
      finder_method = Clavis.configuration.user_finder_method

      if user_class.respond_to?(finder_method)
        user_class.public_send(finder_method, auth_hash)
      else
        # If no suitable method is available, just return the auth hash
        auth_hash
      end
    end

    # Method to handle authentication requests with proper routing
    def request_authentication
      session[:return_to_after_authenticating] = request.url

      # Only redirect to paths we control or to root_path
      # This avoids assumptions about the host application's routes
      redirect_to main_app.root_path, alert: "Authentication required. Please sign in to continue."
    end

    def after_authentication_url
      return session.delete(:return_to_after_authenticating) if session[:return_to_after_authenticating].present?

      # Try to get main_app's root_path, fall back to "/"
      begin
        main_app.respond_to?(:root_path) ? main_app.root_path : "/"
      rescue StandardError
        "/"
      end
    end

    def safe_redirect(path = nil)
      # Try default paths in order of preference
      fallback_paths = [
        -> { main_app.root_path if main_app.respond_to?(:root_path) },
        -> { main_app.respond_to?(:login_path) ? main_app.login_path : nil },
        -> { "/" } # Final fallback is always root
      ]

      # Use provided path or find first working fallback
      target_path = path || fallback_paths.lazy.map(&:call).find(&:present?)

      # Perform the redirect with exception handling
      begin
        redirect_to target_path
      rescue StandardError => e
        # Log the error and redirect to root as ultimate fallback
        Clavis::Logging.log_error("Redirect error: #{e.message}. Falling back to '/'")
        redirect_to "/"
      end
    end

    # Override default_path to ensure we don't redirect back to auth paths
    def default_path
      path = if defined?(main_app) && main_app.respond_to?(:root_path)
               main_app.root_path
             else
               "/"
             end

      Rails.logger.debug "CLAVIS DEBUG: Using default path: #{path}"
      path
    end
  end
end
