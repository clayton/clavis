# frozen_string_literal: true

# This file is for specs that require a Rails environment
ENV["RAILS_ENV"] ||= "test"

# Load the dummy Rails application
require_relative "dummy/config/environment"

# Prevent database truncation if the environment is production
abort("The Rails environment is in production mode!") if Rails.env.production?

require "rspec/rails"

RSpec.configure do |config|
  # Include Rails testing helpers
  config.include Rails.application.routes.url_helpers
  config.include ActionView::TestCase::Behavior, type: :helper
  config.include ActionDispatch::TestProcess::FixtureFile

  # Reset Clavis configuration before each test
  config.before(:each) do
    Clavis.reset_configuration!

    # Configure Clavis for testing
    Clavis.setup do |c|
      c.providers = {
        google: {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "http://localhost:3000/auth/google/callback"
        },
        facebook: {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "http://localhost:3000/auth/facebook/callback"
        }
      }
    end
  end
end
