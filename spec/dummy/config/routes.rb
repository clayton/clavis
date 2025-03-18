# frozen_string_literal: true

Rails.application.routes.draw do
  root to: "home#index"

  # Sessions routes
  get "login", to: "sessions#new", as: :new_session
  post "login", to: "sessions#create", as: :sessions
  delete "logout", to: "sessions#destroy", as: :session

  # Mount Clavis engine
  mount Clavis::Engine, at: "/auth"
end
