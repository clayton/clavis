# frozen_string_literal: true

require "rails/generators"

module Clavis
  module Generators
    class ControllerGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      argument :controller_name, type: :string, default: "Auth"

      class_option :skip_routes, type: :boolean, default: false, desc: "Skip route generation"

      def create_controller
        template "controller.rb.tt", "app/controllers/#{file_name}_controller.rb"
      end

      def create_views
        template "views/login.html.erb.tt", "app/views/#{file_name}/login.html.erb"
      end

      def add_routes
        return if options[:skip_routes]

        route_config = <<~ROUTES
          # OAuth routes
          get '/auth/:provider', to: '#{file_name}#authorize', as: :auth
          get '/auth/:provider/callback', to: '#{file_name}#callback', as: :auth_callback
          get '/auth/failure', to: '#{file_name}#failure', as: :auth_failure
          get '/login', to: '#{file_name}#login', as: :login
          delete '/logout', to: '#{file_name}#logout', as: :logout
        ROUTES

        route route_config
      end

      private

      def file_name
        controller_name.underscore
      end

      def class_name
        controller_name.camelize
      end
    end
  end
end
