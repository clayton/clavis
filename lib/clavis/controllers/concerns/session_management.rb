# frozen_string_literal: true

require "active_support/concern"

module Clavis
  module Controllers
    module Concerns
      # SessionManagement provides methods for handling user sessions after OAuth authentication
      # This concern is designed to be included in ApplicationController and provides
      # a simple, Rails-friendly way to handle user sessions.
      module SessionManagement
        extend ActiveSupport::Concern

        included do
          helper_method :current_user, :authenticated? if respond_to?(:helper_method)
        end

        # Check if a user is currently authenticated
        # @return [Boolean] Whether the user is authenticated
        def authenticated?
          current_user.present?
        end

        # Get the current authenticated user, if any
        # @return [User, nil] The current user or nil if not authenticated
        def current_user
          return @current_user if defined?(@current_user)

          @current_user = find_user_by_cookie
        end

        # Sign in a user by setting a signed cookie
        # @param user [User] The user to sign in
        def sign_in_user(user)
          # First try to use Devise if it's available
          if respond_to?(:sign_in) && !method("sign_in").owner.is_a?(Method)
            sign_in(user)
          else
            # Use our secure cookie-based approach
            cookies.signed.permanent[:user_id] = {
              value: user.id,
              httponly: true,
              same_site: :lax,
              secure: Rails.env.production?
            }
          end
        end

        # Sign out the current user by clearing the cookie
        # @return [void]
        def sign_out_user
          # First try to use Devise if it's available
          if respond_to?(:sign_out) && !method("sign_out").owner.is_a?(Method)
            sign_out(current_user)
          else
            # Use our cookie-based approach
            cookies.delete(:user_id)
          end
        end

        # Store the current URL to return to after authentication
        # @return [void]
        def store_location
          session[:return_to] = request.url if request.get?
        end

        # Default path to redirect to after successful login
        # @return [String] The path to redirect to
        def after_login_path
          stored_location || default_path
        end

        # Default path to redirect to after logout
        # @return [String] The path to redirect to
        def after_logout_path
          if respond_to?(:login_path)
            login_path
          else
            default_path
          end
        end

        private

        # Get the stored location for redirection
        # @return [String, nil] The stored location or nil
        def stored_location
          location = session.delete(:return_to)

          # Don't return auth paths to avoid redirect loops
          return unless location.present? && !location.to_s.include?("/auth/")

          location
        end

        # Default path when no stored location is available
        # @return [String] The default path
        def default_path
          if defined?(main_app) && main_app.respond_to?(:root_path)
            main_app.root_path
          else
            "/"
          end
        end

        # Find a user by the signed cookie
        # @return [User, nil] The user or nil if not found
        def find_user_by_cookie
          return nil unless cookies.signed[:user_id]

          user_class = Clavis.configuration.user_class.constantize
          user_class.find_by(id: cookies.signed[:user_id])
        end
      end
    end
  end
end
