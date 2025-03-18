# frozen_string_literal: true

# This file is used for specs that require a Rails environment
ENV["RAILS_ENV"] ||= "test"

# Add clavis lib to load path
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

# Try to clear any existing Rails/ActiveRecord constants to avoid conflicts
Object.send(:remove_const, :Rails) if defined?(Rails)
Object.send(:remove_const, :ActiveRecord) if defined?(ActiveRecord)
Object.send(:remove_const, :ActionController) if defined?(ActionController)
Object.send(:remove_const, :ActionView) if defined?(ActionView)

# Configure Rails Environment
require_relative "dummy/config/environment"

# Prevent database truncation if the environment is production
abort("The Rails environment is running in production mode!") if Rails.env.production?

# Load RSpec Rails
require "rspec/rails"

# Load Capybara for feature tests
require "capybara/rails"
require "capybara/rspec"

# Make sure the engine is loaded
require "clavis"
require "clavis/engine"

# Load OmniAuth for authentication tests if available
begin
  require "omniauth"
rescue LoadError
  puts "OmniAuth not available. Authentication tests may be skipped."
end

# Load support files (excluding any already loaded)
Dir[File.expand_path("support/**/*.rb", __dir__)].sort.each do |f|
  next if f.include?("mocks/") && File.basename(f) != "README.md" # Skip mocks, we're in Rails mode

  require f
end

# Set up in-memory database for testing
ActiveRecord::Base.establish_connection(
  adapter: "sqlite3",
  database: ":memory:"
)

# Load the schema
ActiveRecord::Schema.verbose = false
load File.expand_path("dummy/db/schema.rb", __dir__)

# Add helpers for fixture files
module FixtureHelpers
  def json_fixture(name)
    JSON.parse(File.read(File.expand_path("fixtures/files/#{name}.json", __dir__)))
  end
end

# Configure RSpec
RSpec.configure do |config|
  # Include Rails route helpers
  config.include Rails.application.routes.url_helpers

  # Include Clavis helpers
  config.include Clavis::ViewHelpers if defined?(Clavis::ViewHelpers)

  # Include controller test helpers
  config.include Devise::Test::ControllerHelpers, type: :controller if defined?(Devise)

  # Use transactional fixtures for ActiveRecord tests
  config.use_transactional_fixtures = true

  # Infer spec type from file location
  config.infer_spec_type_from_file_location!

  # Filter lines from Rails gems in backtraces
  config.filter_rails_from_backtrace!

  # Reset Clavis configuration before each test
  config.before(:each) do
    Clavis.reset_configuration! if Clavis.respond_to?(:reset_configuration!)

    # Set up Clavis for each test
    Clavis.configure do |c|
      # Set up test providers
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

      # Set redirect paths (using custom attributes if we add them to the configuration)
      c.default_callback_path = "/auth/:provider/callback"
      c.enforce_https = false # Disable HTTPS enforcement for testing
      c.allowed_redirect_hosts = ["localhost"]
    end
  end

  config.include FixtureHelpers
end

# Set up OmniAuth test mode
OmniAuth.config.test_mode = true if defined?(OmniAuth)
