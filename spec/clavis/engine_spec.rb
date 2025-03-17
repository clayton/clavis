# frozen_string_literal: true

require "spec_helper"

# Since the Engine is only loaded in a Rails environment, we need to check if it's defined
if defined?(Clavis::Engine)
  RSpec.describe Clavis::Engine do
    it "integrates with Rails as an engine" do
      skip "This test requires a Rails environment"
      # This test would verify that the engine mounts properly in a Rails application
      # expect(Rails.application.routes.routes).to include(route_for('/auth/:provider/callback'))
    end

    describe "initializers" do
      let(:app) { double("app") }
      let(:initializer) { described_class.initializers.find { |i| i.name == name } }

      context "clavis.helpers" do
        let(:name) { "clavis.helpers" }

        it "exists" do
          expect(initializer).not_to be_nil
        end

        it "loads helpers into ActionController" do
          action_controller_load_hook = double("action_controller_load_hook")
          action_view_load_hook = double("action_view_load_hook")
          after_initialize_hook = double("after_initialize_hook")

          allow(ActiveSupport).to receive(:on_load).with(:action_controller).and_yield(action_controller_load_hook)
          allow(ActiveSupport).to receive(:on_load).with(:action_view).and_yield(action_view_load_hook)
          allow(ActiveSupport).to receive(:on_load).with(:after_initialize).and_yield(after_initialize_hook)

          expect(action_controller_load_hook).to receive(:include).with(Clavis::Controllers::Concerns::Authentication)
          expect(action_view_load_hook).to receive(:include).with(Clavis::ViewHelpers)

          # Mock ApplicationHelper for after_initialize
          application_helper = Class.new
          stub_const("ApplicationHelper", application_helper)
          expect(application_helper).to receive(:include).with(Clavis::ViewHelpers)
          allow(application_helper).to receive(:included_modules).and_return([])

          initializer.run(app)
        end
      end
    end
  end
else
  RSpec.describe "Clavis::Engine (Rails integration)" do
    it "requires a Rails environment to be tested" do
      skip "This test requires a Rails environment"
    end
  end
end

# Test the helpers functionality without requiring the engine
RSpec.describe "Clavis helpers integration" do
  it "includes view helpers in ActionView" do
    skip "This test requires a Rails environment"
    # In a real Rails app, this would test that the view helpers are included
  end

  it "includes authentication concern in ActionController" do
    skip "This test requires a Rails environment"
    # In a real Rails app, this would test that the authentication concern is included
  end

  it "makes view helpers available in ApplicationHelper" do
    skip "This test requires a Rails environment"
    # In a real Rails app, this would test that the view helpers are included in ApplicationHelper
  end
end
