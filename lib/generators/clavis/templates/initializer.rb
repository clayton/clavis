# frozen_string_literal: true

Clavis.configure do |config|
  # Configure your OAuth providers here
  config.providers = {
<% providers.each do |provider| %>
    <%= provider %>: {
      client_id: ENV["<%= provider.upcase %>_CLIENT_ID"] || Rails.application.credentials.dig(:<%= provider %>, :client_id),
      client_secret: ENV["<%= provider.upcase %>_CLIENT_SECRET"] || Rails.application.credentials.dig(:<%= provider %>, :client_secret),
      # IMPORTANT: This exact URI must be registered in the <%= provider.capitalize %> developer console/dashboard
      # For example, in Google Cloud Console: APIs & Services > Credentials > OAuth 2.0 Client IDs > Authorized redirect URIs
      redirect_uri: "http://localhost:3000/auth/<%= provider %>/callback" # Change this in production
    },
<% end %>
  }

  # Default scopes to request from providers
  # config.default_scopes = "email profile"

  # Enable verbose logging for debugging
  # config.verbose_logging = true
  
  # User class and finder method
  # These settings control how Clavis finds or creates users from OAuth data
  # config.user_class = "User" # The class to use for user creation/lookup
  # config.user_finder_method = :find_or_create_from_clavis # The method to call on user_class
  #
  # Make sure to add this method to your User model:
  #   rails generate clavis:user_method
  #
  # Or implement it manually with your custom logic

  # Custom claims processor
  # config.claims_processor = proc do |auth_hash, user|
  #   # Process specific claims
  #   if auth_hash[:provider] == "google" && auth_hash[:info][:email_verified]
  #     user.verified_email = true
  #   end
  # end
end 