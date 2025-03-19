# frozen_string_literal: true

require "rails/generators"

module Clavis
  module Generators
    class UserMethodGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      desc "Adds the find_or_create_from_clavis method to your User model"

      def add_user_method
        user_file = "app/models/user.rb"

        if File.exist?(user_file)
          # Check if the method already exists
          user_content = File.read(user_file)
          if user_content.include?("def self.find_or_create_from_clavis")
            say_status :skip, "find_or_create_from_clavis method already exists in User model", :yellow
            return
          end

          # Add the method
          inject_into_file user_file, before: /end\s*\Z/ do
            <<-'RUBY'

  # Find or create a user from OAuth authentication
  # This method is called by Clavis when authenticating via OAuth
  def self.find_or_create_from_clavis(auth_hash)
    # First try to find an existing identity
    identity = Clavis::OauthIdentity.find_by(
      provider: auth_hash[:provider],
      uid: auth_hash[:uid]
    )
    return identity.user if identity&.user

    # Try to find by email if available
    user = User.find_by(email: auth_hash.dig(:info, :email)) if auth_hash.dig(:info, :email)

    # Create a new user if none exists
    if user.nil?
      user = User.new(
        email: auth_hash.dig(:info, :email),
        name: auth_hash.dig(:info, :name) || "User_#{SecureRandom.hex(4)}"
        # Add any other required fields for your User model here
      )
      
      # Set a random password if required
      if user.respond_to?(:password=)
        password = SecureRandom.hex(16)
        user.password = password
        user.password_confirmation = password if user.respond_to?(:password_confirmation=)
      end
      
      user.save!
    end

    # Create or update the OAuth identity for this user
    identity = Clavis::OauthIdentity.find_or_initialize_by(
      provider: auth_hash[:provider],
      uid: auth_hash[:uid]
    )
    
    identity.update!(
      user: user,
      auth_data: auth_hash[:info],
      token: auth_hash.dig(:credentials, :token),
      refresh_token: auth_hash.dig(:credentials, :refresh_token),
      expires_at: auth_hash.dig(:credentials, :expires_at)
    )

    user
  end
            RUBY
          end

          say_status :insert, "Added find_or_create_from_clavis method to User model", :green
        else
          user_template = <<~'RUBY'
            class User < ApplicationRecord
              # Find or create a user from OAuth authentication
              # This method is called by Clavis when authenticating via OAuth
              def self.find_or_create_from_clavis(auth_hash)
                # First try to find an existing identity
                identity = Clavis::OauthIdentity.find_by(
                  provider: auth_hash[:provider],
                  uid: auth_hash[:uid]
                )
                return identity.user if identity&.user

                # Try to find by email if available
                user = User.find_by(email: auth_hash.dig(:info, :email)) if auth_hash.dig(:info, :email)

                # Create a new user if none exists
                if user.nil?
                  user = User.new(
                    email: auth_hash.dig(:info, :email),
                    name: auth_hash.dig(:info, :name) || "User_#{SecureRandom.hex(4)}"
                    # Add any other required fields for your User model here
                  )
                  
                  # Set a random password if required
                  if user.respond_to?(:password=)
                    password = SecureRandom.hex(16)
                    user.password = password
                    user.password_confirmation = password if user.respond_to?(:password_confirmation=)
                  end
                  
                  user.save!
                end

                # Create or update the OAuth identity for this user
                identity = Clavis::OauthIdentity.find_or_initialize_by(
                  provider: auth_hash[:provider],
                  uid: auth_hash[:uid]
                )
                
                identity.update!(
                  user: user,
                  auth_data: auth_hash[:info],
                  token: auth_hash.dig(:credentials, :token),
                  refresh_token: auth_hash.dig(:credentials, :refresh_token),
                  expires_at: auth_hash.dig(:credentials, :expires_at)
                )

                user
              end
            end
          RUBY

          # Create the user model file
          create_file user_file, user_template
          say_status :create, "Created User model with find_or_create_from_clavis method", :green
        end
      end

      def show_instructions
        say "\nA find_or_create_from_clavis method has been added to your User model."
        say "This method will be called by Clavis when a user authenticates via OAuth."
        say "You should customize this method to fit your application's needs, particularly:"
        say "  - Adding any additional required fields for your User model"
        say "  - Handling any special cases for your application"
        say "\nFor more information, see the Clavis documentation."
      end
    end
  end
end
