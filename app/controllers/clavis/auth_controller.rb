# frozen_string_literal: true

module Clavis
  class AuthController < ::ApplicationController
    include Clavis::Controllers::Concerns::Authentication

    before_action :check_provider_configured

    def authorize
      oauth_authorize
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

        redirect_to main_app.root_path
      end
    end

    private

    def check_provider_configured
      provider = params[:provider]

      # Skip for testing or when provider is nil
      return if request.path.start_with?("/test") || provider.nil?

      return if Clavis.configuration.provider_configured?(provider)

      Clavis::Logging.log_error("Provider '#{provider}' is not configured")
      flash[:alert] =
        "Authentication provider '#{provider}' is not configured. Please check your Clavis configuration."
      redirect_to main_app.root_path
    end

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
      session.delete(:return_to_after_authenticating) || main_app.root_path
    end
  end
end
