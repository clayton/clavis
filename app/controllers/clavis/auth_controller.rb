# frozen_string_literal: true

module Clavis
  class AuthController < ::ApplicationController
    include Clavis::Controllers::Concerns::Authentication

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

    def find_or_create_user_from_oauth(auth_hash)
      if defined?(User) && User.respond_to?(:find_for_oauth)
        User.find_for_oauth(auth_hash)
      else
        # If no User model is available, just return the auth hash
        auth_hash
      end
    end
  end
end
