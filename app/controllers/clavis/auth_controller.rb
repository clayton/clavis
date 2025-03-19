# frozen_string_literal: true

module Clavis
  # AuthController directly inherits from ActionController::Base to avoid inheriting
  # host application's authentication requirements or before_actions that could
  # interfere with the OAuth flow
  class AuthController < ::ActionController::Base
    include Clavis::Controllers::Concerns::Authentication

    # Add basic controller setup
    protect_from_forgery with: :exception

    # Allow access to main_app routes
    helper Rails.application.routes.url_helpers if defined?(Rails)

    # Skip CSRF protection for OAuth callback endpoints since they come from external redirects
    skip_before_action :verify_authenticity_token, only: [:callback]

    def authorize
      Rails.logger.debug "CLAVIS DEBUG: AuthController#authorize called with params: #{params.inspect}"
      oauth_authorize
      Rails.logger.debug "CLAVIS DEBUG: AuthController#authorize completed"
    end

    def callback
      oauth_callback do |user, auth_hash|
        # This is a default implementation that can be overridden
        # by the application using the gem
        if respond_to?(:clavis_authentication_success)
          clavis_authentication_success(user, auth_hash)
        else
          # Default behavior: set user_id in session and redirect to root
          session[:user_id] = user.id if user.respond_to?(:id)
          redirect_to main_app.root_path, notice: "Successfully signed in with #{params[:provider].capitalize}"
        end
      end
    rescue Clavis::AuthenticationError => e
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

        # Safe redirect to root_path or fallback to "/"
        safe_redirect
      end
    end

    private

    def find_or_create_user_from_oauth(auth_hash)
      if defined?(User) && User.respond_to?(:find_for_oauth)
        User.find_for_oauth(auth_hash)
      else
        # If no User model is available, just return the auth hash
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
  end
end
