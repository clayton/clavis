# frozen_string_literal: true

class ApplicationController < ActionController::Base
  # Ensure CSRF tokens are verified
  protect_from_forgery with: :exception

  # Add a helper method for accessing the current user
  helper_method :current_user

  # This is the base controller for the dummy app
  include Clavis::Controllers::Concerns::Authentication if defined?(Clavis::Controllers::Concerns::Authentication)

  private

  def current_user
    @current_user ||= session[:user_id] && User.find_by(id: session[:user_id])
  end

  def authenticate_user!
    return if current_user

    redirect_to new_session_path, alert: "Please sign in to continue."
  end
end
