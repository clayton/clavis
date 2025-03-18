# frozen_string_literal: true

Clavis.setup do |config|
  # Set OmniAuth test mode for our specs
  OmniAuth.config.test_mode = true

  # Configure providers
  config.providers = {
    google: {
      client_id: "test_google_client_id",
      client_secret: "test_google_client_secret",
      options: {
        scope: "email,profile"
      }
    },
    facebook: {
      client_id: "test_facebook_client_id",
      client_secret: "test_facebook_client_secret",
      options: {
        scope: "email,public_profile"
      }
    }
  }

  # Configure the user model
  config.user_model = "User"

  # Configure how to find or create users
  config.find_user_method = :find_for_oauth

  # Optional redirect paths
  config.redirect_paths = {
    after_sign_in: "/",
    after_sign_out: "/login"
  }
end
