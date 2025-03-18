# frozen_string_literal: true

Clavis::Engine.routes.draw do
  get "/:provider", to: "auth#authorize", as: :clavis_authorize
  get "/:provider/callback", to: "auth#callback", as: :clavis_callback
end
