# frozen_string_literal: true

class User < ApplicationRecord
  # Only include OauthAuthenticatable if it's defined
  include Clavis::Models::OauthAuthenticatable if defined?(Clavis::Models::OauthAuthenticatable)

  # Include ActiveModel modules if they're defined
  if defined?(ActiveModel)
    include ActiveModel::Model
    include ActiveModel::AttributeMethods
    include ActiveModel::Conversion
    include ActiveModel::Dirty
  end

  attr_accessor :id, :email, :name, :first_name, :last_name

  # Use a class instance variable to store users for testing
  @users = []

  class << self
    attr_accessor :users
  end

  validates :email, presence: true, uniqueness: true if defined?(ActiveModel::Validations)

  def initialize(attributes = {})
    # Set default values
    @id = rand(1000)

    # Set attributes
    attributes.each do |key, value|
      send(:"#{key}=", value) if respond_to?(:"#{key}=")
    end

    # Add to users collection
    self.class.users << self unless self.class.users.any? { |user| user.id == @id }
  end

  def persisted?
    true
  end

  # A class method to allow finding by attributes
  def self.find_by(attributes = {})
    @users.find do |user|
      attributes.all? { |key, value| user.send(key) == value }
    end
  end

  # A class method to create a user from OAuth data
  def self.find_for_oauth(auth_hash)
    email = auth_hash.dig(:info, :email)
    return nil unless email

    user = find_by(email: email) || new(email: email)

    # Update user details from the auth hash
    if auth_hash[:info]
      user.name = auth_hash[:info][:name] if auth_hash[:info][:name]
      user.first_name = auth_hash[:info][:first_name] || auth_hash[:info][:given_name]
      user.last_name = auth_hash[:info][:last_name] || auth_hash[:info][:family_name]
    end

    # Call save to maintain compatibility with both ActiveRecord and our mocks
    user.save! if user.respond_to?(:save) && (user.respond_to?(:changed?) ? user.changed? : true)
    user
  end

  # Define a save method that always returns true if we're in a non-ActiveRecord context
  unless method_defined?(:save)
    def save
      true
    end
  end

  # Define a save! method that always returns true if we're in a non-ActiveRecord context
  unless method_defined?(:save!)
    def save!
      true
    end
  end

  # Create a test user if none exists
  new(id: 1, email: "test@example.com", name: "Test User", first_name: "Test", last_name: "User") if @users.empty?
end
