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
    template_content = File.read("lib/generators/clavis/templates/add_oauth_to_users.rb")
    expect(template_content).to include("add_column :users, :oauth_user, :boolean, default: false")
    expect(template_content).to include("add_column :users, :avatar_url, :string")
    expect(template_content).to include("add_column :users, :last_oauth_login_at, :datetime")
    expect(template_content).to include("add_column :users, :last_oauth_provider, :string")
    expect(template_content).to include("remove_column :users, :provider, :string")
    expect(template_content).to include("remove_column :users, :uid, :string")
  end

  it "has a valid OauthIdentities migration template" do
    template_files = [
      "lib/generators/clavis/templates/migration.rb",
      "lib/generators/clavis/templates/migration.rb.tt"
    ]

    template_files.each do |file|
      next unless File.exist?(file)

      template_content = File.read(file)
      expect(template_content).to include("t.references :authenticatable, polymorphic: true")
      expect(template_content).to include("t.string :provider, null: false")
      expect(template_content).to include("t.string :uid, null: false")
      expect(template_content).to include("t.index [:provider, :uid], unique: true")
    end
  end
end
