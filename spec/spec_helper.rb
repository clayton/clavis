# frozen_string_literal: true

require "rspec"
require "logger"
require "ostruct"
require "active_support/core_ext/numeric/time"
require "active_support/core_ext/integer/time"
require "active_support/core_ext/time/calculations"

# Load mocks for testing
require_relative "support/mocks"
require_relative "support/mock_providers"

# Load Clavis
require "clavis"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  # Reset Clavis configuration before each test
  config.before(:each) do
    Clavis.reset_configuration!
  end

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Skip Rails-dependent tests if Rails is not available
  config.before(:each, :rails) do |_example|
    skip "Rails is not available" unless defined?(Rails)
  end
end
