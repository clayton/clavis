# frozen_string_literal: true

require "rails/generators/active_record"

module Clavis
  module Generators
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      def copy_migration
        migration_template "migration.rb.tt", "db/migrate/create_clavis_oauth_identities.rb",
                           migration_version: migration_version
      end

      def create_initializer
        template "initializer.rb.tt", "config/initializers/clavis.rb"
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
      end
    end
  end
end
