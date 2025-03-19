# frozen_string_literal: true

# This file is used by specs that need to test routes without conflicts
# when running the full test suite

require "spec_helper"

# Instead of disabling the route setup completely, let's use a mechanism
# that ensures routes are set up in a way that avoids name conflicts
# Only set up routes if not already done by a previous test
if defined?(Clavis::Engine) && !Clavis::Engine.instance_variable_get(:@isolated_test_routes_setup)
  # If we're in a route conflict scenario, modify the route naming pattern
  route_namespace_method = Clavis::Engine.method(:route_namespace_id)

  # Save the original method if we need to restore it
  Clavis::Engine.instance_variable_set(:@original_route_namespace_id, route_namespace_method)

  # Create a unique namespace for our isolated tests
  Clavis::Engine.define_singleton_method(:route_namespace_id) do
    "clavis_isolated_#{rand(10_000)}"
  end

  # Mark that we've set up our isolated test approach
  Clavis::Engine.instance_variable_set(:@isolated_test_routes_setup, true)
end

# Continue with regular spec setup
