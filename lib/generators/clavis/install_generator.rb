# frozen_string_literal: true

require "rails/generators/base"

module Clavis
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      class_option :providers, type: :array, default: ["google"],
                               desc: "List of providers to configure (google, github, apple, facebook, microsoft)"

      def create_initializer
        template "initializer.rb", "config/initializers/clavis.rb"
      end

      def create_migration
        if ActiveRecord::Base.connection.table_exists?(:users)
          migration_template "migration.rb", "db/migrate/add_oauth_to_users.rb", skip: true
        else
          say "Skipping migration because users table doesn't exist. " \
              "Run 'rails g model User' first or create the table manually."
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
        say "3. Add provider buttons to your views: <%= oauth_button :google %>"
        say "\nFor more information, see the documentation at https://github.com/clayton/clavis"
      end

      private

      def migration_template(source, destination, config = {})
        migration_dir = File.dirname(destination)
        migration_name = File.basename(destination, File.extname(destination))

        return if migration_exists?(migration_dir, migration_name)

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
