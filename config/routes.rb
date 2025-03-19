# frozen_string_literal: true

Clavis::Engine.routes.draw do
  # Class variable to track registered routes
  unless Clavis::Engine.instance_variable_defined?(:@registered_routes)
    Clavis::Engine.instance_variable_set(:@registered_routes,
                                         Set.new)
  end
  registered_routes = Clavis::Engine.instance_variable_get(:@registered_routes)

  # These routes will be prefixed by the engine mount point (e.g., /auth)
  # No additional module scope needed since the engine already has Clavis namespace
  scope do
    # Provider-specific named routes
    Clavis::Configuration::SUPPORTED_PROVIDERS.each do |provider|
      route_name = "auth_#{provider}"
      callback_route_name = "auth_#{provider}_callback"

      unless registered_routes.include?(route_name)
        # Routes inside engine are relative to mount point, so no additional /auth prefix
        get "/#{provider}", to: "auth#authorize", as: route_name, defaults: { provider: provider }
        registered_routes << route_name
      end

      unless registered_routes.include?(callback_route_name)
        get "/#{provider}/callback", to: "auth#callback", as: callback_route_name, defaults: { provider: provider }
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

# We don't need to define additional application routes, since all should go through
# the engine when mounted at /auth
Clavis::Engine.setup_routes = lambda do |_app|
  # Just log that routes are set up and no action is needed
  Rails.logger.info("Clavis engine is mounted. Use engine routes via engine route helpers.")
end
