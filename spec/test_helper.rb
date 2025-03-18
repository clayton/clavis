# frozen_string_literal: true

# Configure Rails Environment
ENV["RAILS_ENV"] = "test"

# Add the Clavis lib to load path
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

# Configure environment variables for testing
ENV["OAUTH_REDIRECT_URI"] ||= "http://localhost:3000/auth/callback"
ENV["OAUTH_CLIENT_ID"] ||= "test_client_id"
ENV["OAUTH_CLIENT_SECRET"] ||= "test_client_secret"

# Load the Rails dummy application
require File.expand_path("dummy/config/environment.rb", __dir__)

# Load Rails test helpers
require "rails/test_help"
require "rspec/rails"
require "capybara/rails"
require "capybara/rspec"

# Load support files
Dir[File.expand_path("support/**/*.rb", __dir__)].sort.each { |f| require f }

# Configure ActiveRecord for in-memory SQLite
ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
ActiveRecord::Schema.verbose = false
load File.expand_path("dummy/db/schema.rb", __dir__)

# Set file fixture path
ActiveSupport::TestCase.file_fixture_path = File.expand_path("fixtures/files", __dir__)

# Set up OmniAuth test mode
OmniAuth.config.test_mode = true

# Helpers for testing
module TestHelpers
  def json_fixture(name)
    JSON.parse(File.read(File.expand_path("fixtures/files/#{name}.json", __dir__)))
  end

  def google_oauth_response
    json_fixture("google/oauth_response")
  end

  def facebook_oauth_response
    json_fixture("facebook/oauth_response")
  end

  def apple_oauth_response
    json_fixture("apple/oauth_response")
  end

  def setup_test_routes
    Rails.application.routes.draw do
      mount Clavis::Engine, at: "/auth"
      root to: "home#index"
    end
  end

  def setup_clavis_for_testing
    Clavis.configure do |c|
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
        },
        apple: {
          client_id: "test-client-id",
          client_secret: "test-client-secret",
          redirect_uri: "http://localhost:3000/auth/apple/callback",
          team_id: "test-team-id",
          key_id: "test-key-id",
          private_key: "test-private-key"
        }
      }

      c.user_model = "User"
      c.find_user_method = :find_for_oauth
      c.redirect_paths = {
        after_sign_in: "/",
        after_sign_out: "/login"
      }
    end
  end
end

# Include test helpers in RSpec
RSpec.configure do |config|
  config.include TestHelpers

  config.before(:each) do
    Clavis.reset_configuration! if Clavis.respond_to?(:reset_configuration!)
    setup_clavis_for_testing
  end
end
