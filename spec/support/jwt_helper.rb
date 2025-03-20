# frozen_string_literal: true

# JWT helper that properly mocks JWT behavior without redefining the module
require "jwt" unless defined?(JWT)

RSpec.configure do |config|
  config.before(:each) do
    # By default, allow real JWT behaviors
    # Tests can still override these with more specific mocks if needed
    allow(JWT).to receive(:encode).and_call_original
    allow(JWT).to receive(:decode).and_call_original
  end
end
