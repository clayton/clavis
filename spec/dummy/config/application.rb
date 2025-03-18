# frozen_string_literal: true

require_relative "boot"

require "rails/all"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)
require "clavis"
require "clavis/engine"

module Dummy
  class Application < Rails::Application
    # Load an appropriate default version based on Rails version
    if Rails::VERSION::MAJOR >= 8
      # For Rails 8+, use a known version (7.1) to avoid "Unknown version" errors
      config.load_defaults 7.1
    else
      config.load_defaults Rails::VERSION::STRING.to_f
    end

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

    # Set Rails 8.1 timezone handling to avoid deprecation warnings
    if defined?(ActiveSupport) && ActiveSupport.respond_to?(:config) &&
       ActiveSupport.config.respond_to?(:active_support) &&
       ActiveSupport.config.active_support.respond_to?(:to_time_preserves_timezone=)
      config.active_support.to_time_preserves_timezone = :zone
    end
  end
end
