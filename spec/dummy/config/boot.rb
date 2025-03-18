# frozen_string_literal: true

# Make sure dummy app loads its own gems
if ENV["BUNDLE_GEMFILE"].nil? || !File.exist?(ENV.fetch("BUNDLE_GEMFILE", nil))
  ENV["BUNDLE_GEMFILE"] = File.expand_path("../../../Gemfile", __dir__)
end

require "bundler/setup" if File.exist?(ENV["BUNDLE_GEMFILE"])

# Make sure the Clavis gem is loaded from the correct location
$LOAD_PATH.unshift File.expand_path("../../../lib", __dir__)
