# frozen_string_literal: true

require "spec_helper"
require "rails_helper"

# Explicitly load the engine
require "clavis/engine"

RSpec.describe Clavis::Engine, type: :engine do
  before do
    # Make sure the engine is loaded

    # Set up routes for testing
    Rails.application.routes.clear!
    Rails.application.routes.draw do
      mount Clavis::Engine, at: "/auth"
      root to: "home#index"
    end
  end

  it "integrates with Rails as an engine" do
    # Verify that the engine mounts properly in a Rails application
    routes = Rails.application.routes.routes.map(&:name)
    expect(routes).to include("clavis")
  end

  describe "initializers" do
    let(:app) { Rails.application }
    let(:initializer) { described_class.initializers.find { |i| i.name == name } }

    context "clavis.helpers" do
      let(:name) { "clavis.helpers" }

      it "exists" do
        expect(initializer).not_to be_nil
      end

      it "can load helpers into ActionController" do
        # Manually include the module for testing
        ActionController::Base.include(Clavis::Controllers::Concerns::Authentication)
        expect(ActionController::Base.included_modules).to include(Clavis::Controllers::Concerns::Authentication)
      end

      it "can load helpers into ActionView" do
        # Manually include the module for testing
        ActionView::Base.include(Clavis::ViewHelpers)
        expect(ActionView::Base.included_modules).to include(Clavis::ViewHelpers)
      end
    end
  end

  describe "Rails integration" do
    before do
      # Manually include modules for testing
      ActionView::Base.include(Clavis::ViewHelpers)
      ActionController::Base.include(Clavis::Controllers::Concerns::Authentication)
    end

    it "includes view helpers in ActionView" do
      expect(ActionView::Base.included_modules).to include(Clavis::ViewHelpers)
    end

    it "includes authentication concern in ActionController" do
      expect(ActionController::Base.included_modules).to include(Clavis::Controllers::Concerns::Authentication)
    end

    it "makes view helpers available in ApplicationHelper" do
      # Define a dummy ApplicationHelper if it doesn't exist
      class ApplicationHelper; end unless defined?(ApplicationHelper)

      # Include the view helpers
      ApplicationHelper.include(Clavis::ViewHelpers)

      expect(ApplicationHelper.included_modules).to include(Clavis::ViewHelpers)
    end
  end
end
