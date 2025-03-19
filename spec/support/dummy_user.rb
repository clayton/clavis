# frozen_string_literal: true

# This module creates a mock User class that mimics a Rails User model
# for testing purposes when ActiveRecord is not available
module DummyUserSupport
  # Create a dummy User class that responds to find_for_oauth
  class DummyUser
    if defined?(Clavis::Models::Concerns::MockOAuthAuthenticatable)
      include Clavis::Models::Concerns::MockOAuthAuthenticatable
    end

    attr_accessor :id, :email, :name

    def initialize(attributes = {})
      @id = attributes[:id] || 1
      @email = attributes[:email]
      @name = attributes[:name]
      @oauth_identities = []
    end

    def self.find_for_oauth(auth)
      # Find existing user by email or create a new one
      email = auth.dig(:info, :email) || "#{auth[:uid]}@example.com"
      new(email: email, name: auth.dig(:info, :name))

      # Create or update the OAuth identity
    end

    def self.find_by(_conditions)
      # Mock find_by method, always return nil
      nil
    end

    def save
      true
    end
  end

  def self.create_dummy_user
    return if defined?(User)

    # Define User as a plain Ruby class for non-Rails tests
    Object.const_set(:User, Class.new(DummyUser))
  end

  def self.create_rails_user
    return unless
                  defined?(ActiveRecord::Base) &&
                  ActiveRecord::Base.respond_to?(:connection) &&
                  ActiveRecord::Base.connection.present?

    begin
      # Check if the users table needs to be created
      unless ActiveRecord::Base.connection.table_exists?(:users)
        ActiveRecord::Schema.define do
          create_table :users do |t|
            t.string :email
            t.string :name
            t.timestamps
          end
        end
      end

      # Create the RailsUser class if it doesn't exist
      unless defined?(RailsUser)
        # Create a RailsUser class that inherits from ActiveRecord::Base
        klass = Class.new(ApplicationRecord) do
          self.table_name = "users"
          include Clavis::Models::OauthAuthenticatable if defined?(Clavis::Models::OauthAuthenticatable)

          def self.find_for_oauth(auth)
            # Simplified implementation for testing
            user = find_or_initialize_by(email: auth.dig(:info, :email))
            user.attributes = { name: auth.dig(:info, :name) } if auth.dig(:info, :name)
            user.save!
            user
          end
        end

        # Define the RailsUser constant
        DummyUserSupport.const_set(:RailsUser, klass)
      end

      # Override the existing User class if it's a DummyUser
      if defined?(User) && User <= DummyUser
        Object.send(:remove_const, :User)
        Object.const_set(:User, Class.new(RailsUser))
      end
    rescue StandardError => e
      Rails.logger.debug { "Warning: Failed to set up ActiveRecord User model: #{e.message}" }
    end
  end
end

RSpec.configure do |config|
  config.before(:suite) do
    DummyUserSupport.create_dummy_user
  end

  # Set up Rails user for controller tests
  config.before(:each, type: :controller) do
    DummyUserSupport.create_rails_user
  end

  # Set up Rails user for feature tests
  config.before(:each, type: :feature) do
    DummyUserSupport.create_rails_user
  end

  # Set up Rails user for engine tests
  config.before(:each, type: :engine) do
    DummyUserSupport.create_rails_user
  end
end
