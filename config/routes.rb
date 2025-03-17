# frozen_string_literal: true

Clavis::Engine.routes.draw do
  get "/:provider", to: "auth#authorize", as: :authorize
  get "/:provider/callback", to: "auth#callback", as: :callback
end
