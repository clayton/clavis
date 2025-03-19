# frozen_string_literal: true

require "rails/generators"

module Clavis
  module Generators
    class UserMethodGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      desc "Adds Clavis OAuth user methods to your application"

      def create_concern
        # Create directory structure if it doesn't exist
        directory_path = "app/models/concerns"
        FileUtils.mkdir_p(directory_path) unless File.directory?(directory_path)

        # Create the concern file
        create_file "app/models/concerns/clavis_user_methods.rb", <<~RUBY
          # frozen_string_literal: true

          # This concern provides methods for finding or creating users from OAuth data
          # It is intended to be included in your User model
          module ClavisUserMethods
            extend ActiveSupport::Concern
          #{"  "}
            # Include the OauthAuthenticatable module to get helper methods
            included do
              include Clavis::Models::OauthAuthenticatable if defined?(Clavis::Models::OauthAuthenticatable)
          #{"    "}
              # Skip password validation for OAuth users
              # Uncomment this if your User model requires a password but you want to skip it for OAuth users
              # validates :password, presence: true, unless: :oauth_user?
            end
          #{"  "}
            class_methods do
              # Find or create a user from OAuth authentication
              # This method is called by Clavis when authenticating via OAuth
              def find_or_create_from_clavis(auth_hash)
                # First try to find an existing identity
                identity = Clavis::OauthIdentity.find_by(
                  provider: auth_hash[:provider],
                  uid: auth_hash[:uid]
                )
                return identity.user if identity&.user
          #{"  "}
                # Try to find by email if available
                user = find_by(email: auth_hash.dig(:info, :email)) if auth_hash.dig(:info, :email)
          #{"  "}
                # Create a new user if none exists
                if user.nil?
                  # IMPORTANT: These are just example fields. Include only the ones your User model needs.
                  # Available data in auth_hash[:info] typically includes:
                  # - email: The user's email address
                  # - name: The user's full name
                  # - first_name: The user's first name (some providers)
                  # - last_name: The user's last name (some providers)
                  # - nickname: The user's username or handle
                  # - image: URL to the user's profile picture
                  # - location: The user's location (some providers)
                  # - verified: Whether the email is verified (some providers)
                  #
                  # You should include all required fields for YOUR User model.
                  # If your User model requires fields not available from OAuth,#{" "}
                  # you can set defaults or prompt the user to complete their profile later.
          #{"        "}
                  user = new(
                    email: auth_hash.dig(:info, :email),
                    name: auth_hash.dig(:info, :name) || "User_#{SecureRandom.hex(4)}"
                    # Add any other required fields for your User model here
                  )
          #{"        "}
                  # NOTE: For password-protected User models, we recommend using the#{" "}
                  # conditional validation above instead of setting a random password
          #{"        "}
                  user.save!
                end
          #{"  "}
                # Create or update the OAuth identity for this user
                # All OAuth-specific information is stored here, not on the User model
                identity = Clavis::OauthIdentity.find_or_initialize_by(
                  provider: auth_hash[:provider],
                  uid: auth_hash[:uid]
                )
          #{"      "}
                identity.update!(
                  user: user,
                  auth_data: auth_hash[:info],
                  token: auth_hash.dig(:credentials, :token),
                  refresh_token: auth_hash.dig(:credentials, :refresh_token),
                  expires_at: auth_hash.dig(:credentials, :expires_at)
                )
          #{"  "}
                # Optional: Update any fields on the User model that you want to keep in sync
                # user.update(
                #   avatar_url: auth_hash.dig(:info, :image),
                #   last_oauth_login_at: Time.current
                # )
          #{"  "}
                user
              end
            end
          end
        RUBY

        say_status :create, "Created ClavisUserMethods concern", :green
      end

      def update_user_model
        user_file = "app/models/user.rb"

        if File.exist?(user_file)
          # Check if the concern is already included
          user_content = File.read(user_file)
          if user_content.include?("include ClavisUserMethods")
            say_status :skip, "ClavisUserMethods already included in User model", :yellow
            return
          end

          # Add the concern include to the User model
          inject_into_file user_file, after: "class User < ApplicationRecord\n" do
            "  include ClavisUserMethods\n"
          end

          say_status :inject, "Added ClavisUserMethods include to User model", :green
        else
          # Create a User model with the concern included
          create_file user_file, <<~RUBY
            class User < ApplicationRecord
              include ClavisUserMethods
            #{"  "}
              # Add your User model code here
            end
          RUBY

          say_status :create, "Created User model with ClavisUserMethods included", :green
        end
      end

      def show_instructions
        say "\nThe ClavisUserMethods concern has been created and included in your User model."
        say "This gives your User model the ability to find or create users from OAuth data."
        say "\nTo customize how users are created or found:"
        say "  1. Edit app/models/concerns/clavis_user_methods.rb"
        say "  2. Modify the find_or_create_from_clavis method to fit your needs"
        say "\nFor password-protected User models, uncomment the conditional validation in the concern:"
        say "  validates :password, presence: true, unless: :oauth_user?"
        say "\nFor more information, see the Clavis documentation."
      end
    end
  end
end
