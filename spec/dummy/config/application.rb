# frozen_string_literal: true

require_relative "boot"

require "rails/all"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)
require "clavis"

module Dummy
  class Application < Rails::Application
    config.load_defaults Rails::VERSION::STRING.to_f

    # Settings in config/environments/* take precedence over those specified here.
    # Application configuration can go into files in config/initializers
    # -- all .rb files in that directory are automatically loaded after loading
    # the framework and any gems in your application.

    # Only use mini_mime when mime-types is not available
    config.active_storage.use_mini_mime = true if config.respond_to?(:active_storage)

    # Don't generate system test files
    config.generators.system_tests = nil

    # Set up test database
    if config.active_record.sqlite3.respond_to?(:represent_boolean_as_integer)
      config.active_record.sqlite3.represent_boolean_as_integer = true
    end

    # Turn off I18n deprecation warnings
    I18n.enforce_available_locales = false if I18n.respond_to?(:enforce_available_locales=)
  end
end
