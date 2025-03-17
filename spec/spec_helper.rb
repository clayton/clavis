# frozen_string_literal: true

require "rspec"
require "logger"
require "ostruct"

# Load mocks for testing
require_relative "support/mocks"
require_relative "support/mock_providers"

# Load the gem
require "clavis"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Reset Clavis configuration before each test
  config.before(:each) do
    Clavis.reset_configuration!
  end
end
