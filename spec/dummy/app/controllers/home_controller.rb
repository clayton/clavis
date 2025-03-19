# frozen_string_literal: true

class HomeController < ApplicationController
  # Home page - does not require authentication
  skip_before_action :authenticate_user!, only: [:index]

  def index
    # Home page
  end
end
