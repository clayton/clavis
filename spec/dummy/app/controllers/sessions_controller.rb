# frozen_string_literal: true

class SessionsController < ApplicationController
  # Skip authentication for new and create actions
  skip_before_action :authenticate_user!, only: %i[new create], if: -> { respond_to?(:authenticate_user!) }

  def new
    # Login form
  end

  def create
    # Simple authentication for testing
    user = User.find_by(email: params[:email])

    if user && params[:password] == "password" # Very simple auth for testing
      session[:user_id] = user.id
      redirect_to root_path, notice: "Signed in successfully."
    else
      redirect_to new_session_path, alert: "Invalid email or password."
    end
  end

  def destroy
    session.delete(:user_id)
    redirect_to new_session_path, notice: "Signed out successfully."
  end
end
