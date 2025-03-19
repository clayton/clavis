# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"
require "rails/generators/actions"

module Clavis
  module Generators
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration
      include Rails::Generators::Actions

      source_root File.expand_path("templates", __dir__)

      class_option :providers, type: :array, default: ["google"],
                               desc: "List of providers to configure (google, github, apple, facebook, microsoft)"

      # Implement the required next_migration_number method
      # Must be defined as a class method
      def self.next_migration_number(dirname)
        next_migration_number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(next_migration_number)
      end

      def create_initializer
        template "initializer.rb", "config/initializers/clavis.rb"
      end

      def create_migration
        # First, create the OAuth identities table migration if it doesn't exist
        create_identities_migration

        # Then create the User table migration if the users table exists
        create_user_migration
      rescue ActiveRecord::NoDatabaseError
        say "Skipping migration because database doesn't exist. Run 'rails db:create' first."
      end

      def mount_engine
        route "mount Clavis::Engine => '/auth'"
      end

      def show_post_install_message
        say "\nClavis has been installed! Next steps:"
        say "1. Configure your providers in config/initializers/clavis.rb"
        say "2. Run migrations: rails db:migrate"
        say "3. Include the OauthAuthenticatable module in your User model:"
        say "   class User < ApplicationRecord"
        say "     include Clavis::Models::OauthAuthenticatable"
        say "   end"
        say "4. Add OAuth buttons to your views: <%= clavis_oauth_button :google %>"
        say "\nFor more information, see the documentation at https://github.com/clayton/clavis"
      end

      private

      def create_identities_migration
        return if migration_exists?("db/migrate", "create_clavis_oauth_identities")

        migration_number = self.class.next_migration_number("db/migrate")
        @migration_class_name = "CreateClavisOauthIdentities"
        template(
          "migration.rb",
          "db/migrate/#{migration_number}_create_clavis_oauth_identities.rb"
        )
      end

      def create_user_migration
        return if migration_exists?("db/migrate", "add_oauth_to_users")

        # Check if the users table exists
        if ActiveRecord::Base.connection.table_exists?(:users)
          migration_number = self.class.next_migration_number("db/migrate")
          @migration_class_name = "AddOauthToUsers"
          template(
            "add_oauth_to_users.rb",
            "db/migrate/#{migration_number}_add_oauth_to_users.rb"
          )
        else
          say "Skipping User table migration because users table doesn't exist."
          say "Run 'rails g model User' first if you want to add OAuth fields to your User model."
        end
      end

      def migration_exists?(dir, name)
        Dir.glob("#{dir}/[0-9]*_*.rb").grep(/\d+_#{name}.rb$/).first
      end

      def providers
        options[:providers]
      end
    end
  end
end
