# frozen_string_literal: true

require "spec_helper"
require "fileutils"

# This spec is testing the basic structure of the generator without running it
RSpec.describe "Clavis::Generators::InstallGenerator" do
  it "has the correct generator structure" do
    # Instead of running the generator, we're just checking that the file exists
    generator_file = File.expand_path("../../../lib/generators/clavis/install_generator.rb", __dir__)
    expect(File.exist?(generator_file)).to be true

    # Read the content to verify key aspects
    content = File.read(generator_file)
    expect(content).to include("class InstallGenerator < Rails::Generators::Base")
    expect(content).to include("include ActiveRecord::Generators::Migration")
    expect(content).to include("def create_initializer")
    expect(content).to include("def create_migration")
    expect(content).to include("def mount_engine")
  end

  it "has the required template files" do
    templates_dir = File.expand_path("../../../lib/generators/clavis/templates", __dir__)

    # Check that templates directory exists
    expect(Dir.exist?(templates_dir)).to be true

    # Check that required template files exist
    expect(File.exist?(File.join(templates_dir, "initializer.rb"))).to be true
    expect(File.exist?(File.join(templates_dir, "migration.rb"))).to be true
    expect(File.exist?(File.join(templates_dir, "add_oauth_to_users.rb"))).to be true
  end

  it "creates an initializer template with provider configuration" do
    # Read the initializer template
    template_path = File.expand_path("../../../lib/generators/clavis/templates/initializer.rb", __dir__)
    template_content = File.read(template_path)

    # Check for essential parts of the initializer
    expect(template_content).to include("Clavis.configure do |config|")
    expect(template_content).to include("config.providers = {")
  end

  it "has a valid User model migration template" do
    # Read the add_oauth_to_users migration template
    template_path = File.expand_path("../../../lib/generators/clavis/templates/add_oauth_to_users.rb", __dir__)
    template_content = File.read(template_path)

    # Check for essential parts of the migration
    expect(template_content).to include("class AddOauthToUsers < ActiveRecord::Migration")
    expect(template_content).to include("add_column :users, :provider, :string")
    expect(template_content).to include("add_column :users, :uid, :string")
    expect(template_content).to include("add_index :users, %i[provider uid], unique: true")
  end

  it "has a valid OauthIdentities migration template" do
    # Try both migration.rb and migration.rb.tt
    templates_dir = File.expand_path("../../../lib/generators/clavis/templates", __dir__)
    migration_files = ["migration.rb", "migration.rb.tt"]

    # Find a migration file that contains the expected content
    found_valid_template = false

    migration_files.each do |filename|
      template_path = File.join(templates_dir, filename)
      next unless File.exist?(template_path)

      template_content = File.read(template_path)
      unless template_content.include?("CreateClavisOauthIdentities") || template_content.include?("create_table :clavis_oauth_identities")
        next
      end

      # We found a valid template
      expect(template_content).to include("create_table :clavis_oauth_identities")
      expect(template_content).to include("t.references :user")
      expect(template_content).to include("t.string :provider")
      expect(template_content).to include("t.string :uid")
      found_valid_template = true
      break
    end

    # Ensure at least one valid template was found
    expect(found_valid_template).to be(true), "No valid OauthIdentities migration template found"
  end
end
