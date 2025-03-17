# frozen_string_literal: true

Clavis.configure do |config|
  # Configure your OAuth providers here
  config.providers = {
<% providers.each do |provider| %>
    <%= provider %>: {
      client_id: ENV["<%= provider.upcase %>_CLIENT_ID"] || Rails.application.credentials.dig(:<%= provider %>, :client_id),
      client_secret: ENV["<%= provider.upcase %>_CLIENT_SECRET"] || Rails.application.credentials.dig(:<%= provider %>, :client_secret),
      redirect_uri: "http://localhost:3000/auth/<%= provider %>/callback" # Change this in production
    },
<% end %>
  }

  # Default scopes to request from providers
  # config.default_scopes = "email profile"

  # Enable verbose logging for debugging
  # config.verbose_logging = true

  # Custom claims processor
  # config.claims_processor = proc do |auth_hash, user|
  #   # Process specific claims
  #   if auth_hash[:provider] == "google" && auth_hash[:info][:email_verified]
  #     user.verified_email = true
  #   end
  # end
end 