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
              # Add a temporary attribute to track OAuth authentication during user creation
              # This can be used to conditionally skip password validation for OAuth users
              attr_accessor :skip_password_validation
          #{"    "}
              # IMPORTANT: If your User model uses has_secure_password, you need to handle
              # password validation. Uncomment and modify ONE of these approaches:
              #
              # APPROACH 1: Skip password validation for OAuth users (recommended)
              # validates :password, presence: true, length: { minimum: 8 },
              #           unless: -> { skip_password_validation }, on: :create
              #
              # APPROACH 2: Set a random secure password for OAuth users
              # before_validation :set_random_password, if: -> { skip_password_validation && respond_to?(:password=) }
              #
              # APPROACH 3: Use validate: false for OAuth users (less recommended)
              # See the #find_or_create_from_clavis method below
          #{"    "}
              # For approach 2, add this method
              # def set_random_password
              #   self.password = SecureRandom.hex(16)
              #   self.password_confirmation = password if respond_to?(:password_confirmation=)
              # end
            end

            class_methods do
              # Find or create a user from OAuth authentication
              # This method is called by Clavis when authenticating via OAuth
              def find_or_create_from_clavis(auth_hash)
                # First try to find an existing identity
                # For OpenID Connect providers like Google, we use the sub claim as the identifier
                # For other providers, we use the uid
                identity = if auth_hash[:id_token_claims]&.dig(:sub)
                            Clavis::OauthIdentity.find_by(
                              provider: auth_hash[:provider],
                              uid: auth_hash[:id_token_claims][:sub]
                            )
                          else
                            Clavis::OauthIdentity.find_by(
                              provider: auth_hash[:provider],
                              uid: auth_hash[:uid]
                            )
                          end
                return identity.user if identity&.user

                # Extract email from auth_hash (try various possible locations)
                email = extract_email_from_auth_hash(auth_hash)
          #{"      "}
                # Try to find existing user by email if available
                user = find_by(email: email) if email.present?
          #{"      "}
                # Create a new user if none found
                if user.nil?
                  # Convert to HashWithIndifferentAccess for reliable key access
                  info = auth_hash[:info].with_indifferent_access if auth_hash[:info]
                  claims = auth_hash[:id_token_claims].with_indifferent_access if auth_hash[:id_token_claims]
          #{"        "}
                  user = new(
                    email: email
                    # Add other required fields for your User model here, for example:
                    ##{" "}
                    # With HashWithIndifferentAccess, access is reliable regardless of key type:
                    # first_name: info&.dig(:given_name) || info&.dig(:first_name),
                    # last_name: info&.dig(:family_name) || info&.dig(:last_name),
                    # name: info&.dig(:name),
                    # username: info&.dig(:nickname),
                    # avatar_url: info&.dig(:picture) || info&.dig(:image),
                    # terms_accepted: true # for required boolean fields
                  )
          #{"        "}
                  # Mark this user as coming from OAuth to skip password validation
                  # This works with the validation conditionals defined above
                  user.skip_password_validation = true
          #{"        "}
                  # APPROACH 1 & 2: Use standard save with conditional validation
                  user.save!
          #{"        "}
                  # APPROACH 3: Bypass validations entirely - use with caution, and only if approaches 1 & 2 don't work
                  # If your User model has complex validations that are incompatible with OAuth users,
                  # you might need to bypass validations. Uncomment this if needed:
                  # user.save(validate: false)
                end
          #{"  "}
                # Create or update the OAuth identity
                identity = Clavis::OauthIdentity.find_or_initialize_by(
                  provider: auth_hash[:provider],
                  uid: auth_hash[:id_token_claims]&.dig(:sub) || auth_hash[:uid]
                )
                identity.user = user
                identity.auth_data = auth_hash[:info]
                identity.token = auth_hash.dig(:credentials, :token)
                identity.refresh_token = auth_hash.dig(:credentials, :refresh_token)
                identity.expires_at = auth_hash.dig(:credentials, :expires_at) ? Time.at(auth_hash.dig(:credentials, :expires_at)) : nil
                identity.save!
          #{"  "}
                # Set the oauth_user flag if available
                user.update(oauth_user: true) if user.respond_to?(:oauth_user=)
          #{"      "}
                # Optional: Update any fields on the User model that you want to keep in sync
                # user.update(
                #   avatar_url: auth_hash.dig(:info, :image),
                #   last_oauth_login_at: Time.current,
                #   last_oauth_provider: auth_hash[:provider]
                # )
          #{"  "}
                user
              end
          #{"    "}
              private
          #{"    "}
              # Helper method to extract email from various locations in the auth hash
              def extract_email_from_auth_hash(auth_hash)
                return nil unless auth_hash
          #{"      "}
                # Try to get email from various possible locations
                if auth_hash[:info]&.with_indifferent_access
                  info = auth_hash[:info].with_indifferent_access
                  return info[:email] if info[:email].present?
                end
          #{"      "}
                if auth_hash[:id_token_claims]&.with_indifferent_access
                  claims = auth_hash[:id_token_claims].with_indifferent_access
                  return claims[:email] if claims[:email].present?
                end
          #{"      "}
                if auth_hash[:extra]&.dig(:raw_info)&.with_indifferent_access
                  raw_info = auth_hash[:extra][:raw_info].with_indifferent_access
                  return raw_info[:email] if raw_info[:email].present?
                end
          #{"      "}
                nil
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
        # The main instructions will be handled by install_generator.rb
        # This is just a simple confirmation of what was done
        say "\nClavis user methods have been added to your User model."
        say "✅ Created app/models/concerns/clavis_user_methods.rb"
        say "✅ Added 'include ClavisUserMethods' to your User model"
      end
    end
  end
end
