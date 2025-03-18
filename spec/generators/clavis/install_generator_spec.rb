# frozen_string_literal: true

require "spec_helper"

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
  end
end
