# frozen_string_literal: true

require "clavis"
require "rspec"

# Conditionally load Rails for Rails-specific tests
begin
  require "rails"
  require "active_record"
  require "action_controller"
  require "action_view"

  # Set up a minimal Rails application for testing
  class TestApp < Rails::Application
    config.eager_load = false
    config.active_support.deprecation = :stderr
    config.secret_key_base = "test"
  end

  # Initialize the application
  Rails.application.initialize!

  # Set up ActiveRecord
  ActiveRecord::Base.establish_connection(
    adapter: "sqlite3",
    database: ":memory:"
  )

  # Load the engine
  require "clavis/engine"

  # Load the auth controller
  require_relative "../app/controllers/clavis/auth_controller"

  # Load the generators
  require "generators/clavis/install_generator"

  RAILS_LOADED = true
rescue LoadError
  RAILS_LOADED = false
  puts "Rails not loaded. Skipping Rails-specific tests."
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Skip Rails-specific tests if Rails is not loaded
  config.filter_run_excluding rails: true unless RAILS_LOADED
end
