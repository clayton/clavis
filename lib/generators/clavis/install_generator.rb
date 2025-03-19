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

      def add_stylesheets
        # Create the vendor directory if it doesn't exist
        vendor_css_dir = Rails.root.join("vendor", "assets", "stylesheets")
        FileUtils.mkdir_p(vendor_css_dir) unless File.directory?(vendor_css_dir)

        # Copy the CSS template to the vendor directory
        template "clavis.css", "vendor/assets/stylesheets/clavis.css"

        # Create custom styles file in app/assets
        create_file "app/assets/stylesheets/clavis_custom.css", "/* Add your custom Clavis styles here */"

        # For Rails 7+ with Propshaft
        if File.exist?(Rails.root.join("app", "assets", "stylesheets", "application.css"))
          app_css_content = File.read(Rails.root.join("app", "assets", "stylesheets", "application.css"))
          if app_css_content.include?("Propshaft")
            # Create a separate file for Propshaft
            propshaft_css_path = Rails.root.join("app", "assets", "stylesheets", "clavis_styles.css")
            create_file propshaft_css_path, File.read(File.expand_path("clavis.css", source_paths.first))
            say_status :create, "app/assets/stylesheets/clavis_styles.css for Propshaft", :green
            @provide_css_instructions = true
            return
          end
        end

        # Different strategies for different asset pipeline setups
        if File.exist?(Rails.root.join("app", "assets", "stylesheets", "application.scss"))
          append_to_file "app/assets/stylesheets/application.scss", "\n@import 'clavis';\n"
          say_status :insert, "clavis import in application.scss", :green
        elsif File.exist?(Rails.root.join("app", "assets", "stylesheets", "application.css"))
          inject_into_file "app/assets/stylesheets/application.css", " *= require clavis\n", before: "*/",
                                                                                             verbose: false
          say_status :insert, "clavis require in application.css", :green
        elsif File.exist?(Rails.root.join("app", "assets", "stylesheets", "application.css.scss"))
          append_to_file "app/assets/stylesheets/application.css.scss", "\n@import 'clavis';\n"
          say_status :insert, "clavis import in application.css.scss", :green
        else
          say_status :warn, "Could not find main application CSS file", :yellow
          create_file "app/assets/stylesheets/clavis_styles.css",
                      File.read(File.expand_path("clavis.css", source_paths.first))
          say_status :create, "app/assets/stylesheets/clavis_styles.css as fallback", :green
          @provide_css_instructions = true
        end
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
        # Check if the route already exists in the routes file
        routes_content = File.read(Rails.root.join("config/routes.rb"))

        # Only add the route if it doesn't already exist
        if routes_content.include?("mount Clavis::Engine")
          say "Clavis::Engine is already mounted, skipping route addition."
        else
          route "mount Clavis::Engine => '/auth'"
        end
      end

      def show_post_install_message
        say "\nClavis has been installed successfully!"

        # Next steps
        say "\nNext steps:"

        steps = []

        if @provide_css_instructions
          steps << "Include the Clavis styles in your layout:\n   <%= stylesheet_link_tag 'clavis_styles' %>"
        end

        steps << "Configure your providers in config/initializers/clavis.rb"
        steps << "Run migrations: rails db:migrate"
        steps << "Add find_or_create_from_clavis method to your User model:\n   rails generate clavis:user_method"
        steps << "Add OAuth buttons to your views:\n   <%= clavis_oauth_button :google %>"

        # Output numbered steps
        steps.each_with_index do |step, index|
          say "#{index + 1}. #{step}"
        end

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
