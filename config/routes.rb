# frozen_string_literal: true

Clavis::Engine.routes.draw do
  # Class variable to track registered routes
  unless Clavis::Engine.instance_variable_defined?(:@registered_routes)
    Clavis::Engine.instance_variable_set(:@registered_routes,
                                         Set.new)
  end
  registered_routes = Clavis::Engine.instance_variable_get(:@registered_routes)

  scope module: "clavis" do
    # Provider-specific named routes
    Clavis::Configuration::SUPPORTED_PROVIDERS.each do |provider|
      route_name = "auth_#{provider}"
      callback_route_name = "auth_#{provider}_callback"

      unless registered_routes.include?(route_name)
        get "/#{provider}", to: "auth#authorize", as: route_name
        registered_routes << route_name
      end

      unless registered_routes.include?(callback_route_name)
        get "/#{provider}/callback", to: "auth#callback", as: callback_route_name
        registered_routes << callback_route_name
      end
    end

    # Fallback dynamic routes for custom providers
    unless registered_routes.include?("auth")
      get "/:provider", to: "auth#authorize", as: "auth"
      registered_routes << "auth"
    end

    unless registered_routes.include?("auth_callback")
      get "/:provider/callback", to: "auth#callback", as: "auth_callback"
      registered_routes << "auth_callback"
    end
  end
end

# Define a method to add top-level routes to the parent application
# This will be called when the engine is mounted
Clavis::Engine.setup_routes = lambda do |app|
  # Create a class variable on the Engine to track route registration in parent apps
  unless Clavis::Engine.instance_variable_defined?(:@parent_registered_routes)
    Clavis::Engine.instance_variable_set(:@parent_registered_routes,
                                         Set.new)
  end
  parent_registered_routes = Clavis::Engine.instance_variable_get(:@parent_registered_routes)

  app.routes.append do
    # Create provider-specific named routes
    Clavis::Configuration::SUPPORTED_PROVIDERS.each do |provider|
      route_name = "auth_#{provider}"
      callback_route_name = "auth_#{provider}_callback"

      unless parent_registered_routes.include?(route_name)
        get "/auth/#{provider}", to: "clavis/auth#authorize", as: route_name
        parent_registered_routes << route_name
      end

      unless parent_registered_routes.include?(callback_route_name)
        get "/auth/#{provider}/callback", to: "clavis/auth#callback", as: callback_route_name
        parent_registered_routes << callback_route_name
      end
    end

    # Fallback dynamic routes for custom providers
    unless parent_registered_routes.include?("auth")
      get "/auth/:provider", to: "clavis/auth#authorize", as: :auth
      parent_registered_routes << "auth"
    end

    unless parent_registered_routes.include?("auth_callback")
      get "/auth/:provider/callback", to: "clavis/auth#callback", as: :auth_callback
      parent_registered_routes << "auth_callback"
    end
  end
end
