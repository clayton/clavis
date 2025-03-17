# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module Clavis
  module Generators
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      class_option :providers, type: :array, default: ["google"],
                               desc: "List of providers to configure (google, github, apple, facebook, microsoft)"

      def create_initializer
        template "initializer.rb", "config/initializers/clavis.rb"
      end

      def create_migration
        # First, check for the OAuth identities table
        create_oauth_identities_table

        # Then, check for the users table if it exists
        if ActiveRecord::Base.connection.table_exists?(:users)
          migration_template "add_oauth_to_users.rb", "db/migrate/add_oauth_to_users.rb", skip: true
        else
          say "Skipping User table migration because users table doesn't exist."
          say "Run 'rails g model User' first if you want to add OAuth fields to your User model."
        end
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
        say "4. Add OAuth buttons to your views: <%= oauth_button :google %>"
        say "\nFor more information, see the documentation at https://github.com/clayton/clavis"
      end

      private

      def create_oauth_identities_table
        # Check if the table already exists to avoid duplicate migrations
        return if migration_exists?("db/migrate", "create_clavis_oauth_identities")

        migration_template "migration.rb", "db/migrate/create_clavis_oauth_identities.rb", skip: true
      end

      def migration_template(source, destination, config = {})
        migration_dir = File.dirname(destination)
        migration_name = File.basename(destination, File.extname(destination))

        return if config[:skip] && migration_exists?(migration_dir, migration_name)

        config[:migration_template] = true
        config[:skip] = false
        super
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
