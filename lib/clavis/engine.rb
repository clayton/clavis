# frozen_string_literal: true

require "rails"

module Clavis
  class Engine < ::Rails::Engine
    isolate_namespace Clavis

    initializer "clavis.assets" do |app|
      # Add Clavis assets to the asset pipeline
      app.config.assets.paths << root.join("app", "assets", "stylesheets") if app.config.respond_to?(:assets)
      app.config.assets.paths << root.join("app", "assets", "javascripts") if app.config.respond_to?(:assets)
    end

    initializer "clavis.helpers" do
      ActiveSupport.on_load(:action_controller) do
        include Clavis::Controllers::Concerns::Authentication
      end

      ActiveSupport.on_load(:action_view) do
        include Clavis::ViewHelpers
      end
    end

    initializer "clavis.logger" do
      config.after_initialize do
        Clavis::Logging.logger = Rails.logger if defined?(Rails) && Rails.respond_to?(:logger)
      end
    end

    config.to_prepare do
      # Make the view helpers available to the application
      ApplicationController.helper(Clavis::ViewHelpers) if defined?(ApplicationController)
    end
  end
end
