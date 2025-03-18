# frozen_string_literal: true

Clavis::Engine.routes.draw do
  scope module: "clavis" do
    # Use scoped route names based on the engine's namespace identifier
    # This prevents conflicts when the engine is mounted multiple times
    get "/:provider", to: "auth#authorize", as: "#{Clavis::Engine.route_namespace_id}_authorize"
    get "/:provider/callback", to: "auth#callback", as: "#{Clavis::Engine.route_namespace_id}_callback"
  end
end
