# frozen_string_literal: true

Clavis::Engine.routes.draw do
  scope module: "clavis" do
    # Internal namespaced routes - still available for internal use
    get "/:provider", to: "auth#authorize", as: "#{Clavis::Engine.route_namespace_id}_authorize"
    get "/:provider/callback", to: "auth#callback", as: "#{Clavis::Engine.route_namespace_id}_callback"
  end
end

# Define a method to add top-level routes to the parent application
# This will be called when the engine is mounted
Clavis::Engine.setup_routes = lambda do |app|
  app.routes.append do
    # Create top-level routes that map to the engine's auth controller
    get "/auth/:provider", to: "clavis/auth#authorize", as: :auth
    get "/auth/:provider/callback", to: "clavis/auth#callback", as: :auth_callback
  end
end
