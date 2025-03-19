# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

task default: :ci

# Helper method to safely run a Rails command and fix known issues
def safe_rails_command(rails_app_dir, command)
  Dir.chdir(rails_app_dir) do
    # Fix bootsnap issue if needed
    fix_bootsnap_issue

    # Try running the command
    puts "Running: #{command}"
    result = system(command)

    # If it fails, check for asset configuration issues
    unless result
      puts "Command failed, checking for asset configuration issues..."

      # Try to fix assets.rb if it exists
      assets_initializer = "config/initializers/assets.rb"
      if File.exist?(assets_initializer)
        puts "Fixing assets configuration..."
        # Comment out the entire file to prevent issues
        content = File.read(assets_initializer)
        fixed_content = "# Assets configuration disabled for testing\n# Original content:\n# #{content.gsub("\n",
                                                                                                            "\n# ")}"
        File.write(assets_initializer, fixed_content)

        # Try the command again
        puts "Retrying: #{command}"
        result = system(command)
      end
    end

    return result
  end
end

# Helper to fix bootsnap issues and other dependencies in the Rails app
def fix_bootsnap_issue
  boot_rb_path = "config/boot.rb"
  return unless File.exist?(boot_rb_path)

  content = File.read(boot_rb_path)
  return unless content.include?("bootsnap/setup") && !system("bundle list | grep bootsnap")

  puts "Fixing bootsnap issue..."

  # Option 1: Add bootsnap to Gemfile
  unless File.read("Gemfile").include?("bootsnap")
    puts "Adding bootsnap to Gemfile..."
    File.open("Gemfile", "a") do |f|
      f.puts "\n# Reduces boot times through caching; required in config/boot.rb"
      f.puts "gem \"bootsnap\", require: false"
    end
    system("bundle install")
  end

  # Option 2 (fallback): Comment out bootsnap line in boot.rb
  return if system("bundle list | grep bootsnap")

  puts "Commenting out bootsnap in boot.rb..."
  modified_content = content.gsub(
    'require "bootsnap/setup"',
    '# require "bootsnap/setup" # Commented out to avoid dependency issues'
  )
  File.write(boot_rb_path, modified_content)
end

# Helper to test loading the clavis gem
def test_clavis_loading(rails_app_dir)
  Dir.chdir(rails_app_dir) do
    puts "Testing if the clavis gem can be loaded..."
    test_code = "require 'clavis'; puts 'Clavis loaded successfully! Version: ' + Clavis::VERSION"
    system("bundle exec ruby -e \"#{test_code}\"")
  end
end

# Helper to verify and update User model
def update_user_model(rails_app_dir)
  Dir.chdir(rails_app_dir) do
    user_model_path = "app/models/user.rb"
    if File.exist?(user_model_path)
      puts "Updating User model with has_secure_password..."
      user_model_content = File.read(user_model_path)
      unless user_model_content.include?("has_secure_password")
        updated_content = user_model_content.gsub(
          "class User < ApplicationRecord",
          "class User < ApplicationRecord\n  has_secure_password\n  validates :email, presence: true, uniqueness: true"
        )
        File.write(user_model_path, updated_content)
      end
    end
  end
end

# Define an environment task for Rails-dependent tasks
task :environment do
  # This is a no-op task to satisfy dependencies
  # Rails would normally provide this task
end

# Task to run Rails-dependent tests
# rubocop:disable Metrics/BlockLength
namespace :test do
  desc "Run Rails controller tests"
  task controllers: :environment do
    ENV["RAILS_ENV"] = "test"
    system("bundle exec rspec spec/clavis/controllers/*_spec.rb")
  end

  desc "Run Rails integration tests"
  task integration: :environment do
    ENV["RAILS_ENV"] = "test"
    system("bundle exec rspec spec/integration/*_spec.rb")
  end

  desc "Run Rails generator tests"
  task generators: :environment do
    ENV["RAILS_ENV"] = "test"
    system("bundle exec rspec spec/generators/**/*_generator_spec.rb")
  end

  desc "Run all Rails-dependent tests"
  task rails: %i[controllers integration generators]

  desc "Test the actual generator in the rails-app directory"
  task real_generator: :bootstrap_rails_app do
    puts "Testing basic functionality in rails-app..."
    rails_app_dir = File.expand_path("rails-app", __dir__)

    # The bootstrap task ensures the directory exists, so we can remove this check
    # or keep it for extra safety
    unless File.directory?(rails_app_dir)
      puts "Error: rails-app directory not found"
      exit 1
    end

    # Add the gem to the Gemfile if it's not already there
    gemfile_path = File.join(rails_app_dir, "Gemfile")
    gemfile_content = File.read(gemfile_path)

    unless gemfile_content.include?("gem \"clavis\"")
      puts "Adding clavis gem to rails-app Gemfile..."
      # Add the gem with path to local directory
      gem_line = "gem \"clavis\", path: \"../.\""

      # Append to Gemfile
      File.open(gemfile_path, "a") do |f|
        f.puts "\n#{gem_line}"
      end
    end

    # Add bcrypt explicitly - CRITICAL for has_secure_password in the test app
    unless gemfile_content.include?("gem \"bcrypt\"")
      puts "Adding bcrypt directly to Gemfile..."
      File.open(gemfile_path, "a") do |f|
        f.puts "\n# Use Active Model has_secure_password"
        f.puts "gem \"bcrypt\", \"~> 3.1.7\""
      end
    end

    Dir.chdir(rails_app_dir) do
      # Install dependencies
      puts "Installing dependencies in rails-app..."
      unless system("bundle install")
        puts "Error: Failed to install dependencies in rails-app"
        exit 1
      end

      # Test loading the gem
      unless test_clavis_loading(rails_app_dir)
        puts "Error: Failed to load the clavis gem in rails-app"
        exit 1
      end

      # Run our clavis generator
      puts "Running Clavis generator..."
      unless safe_rails_command(rails_app_dir, "bin/rails generate clavis:install")
        puts "Error: Failed to run Clavis generator"
        exit 1
      end

      # Run migrations again after the generator
      puts "Running migrations after generator..."
      unless safe_rails_command(rails_app_dir, "bin/rails db:migrate RAILS_ENV=development") &&
             safe_rails_command(rails_app_dir, "bin/rails db:migrate RAILS_ENV=test")
        puts "Error: Failed to run migrations after generator"
        exit 1
      end

      puts "Generator dependency test in rails-app passed successfully!"
    end
  end
end
# rubocop:enable Metrics/BlockLength

# Task to run all tests
desc "Run all tests including Rails controller tests and integration tests"
task all_tests: [:spec, "test:rails", "test:real_generator"]

# Helper to set up rails app authentication
def setup_rails_authentication(rails_app_dir, gemfile_content)
  Dir.chdir(rails_app_dir) do
    # Add bcrypt first to ensure it's available for has_secure_password
    unless gemfile_content.include?("gem \"bcrypt\"")
      puts "Adding bcrypt to Gemfile..."
      File.open("Gemfile", "a") do |f|
        f.puts "\n# Use Active Model has_secure_password"
        f.puts "gem \"bcrypt\", \"~> 3.1.7\""
      end
      puts "Installing bcrypt..."
      system("bundle install")
    end

    # Generate authentication with User model
    puts "Generating authentication with User model..."
    system("bin/rails generate model User email:string password_digest:string")
    system("bin/rails generate controller Users new create")
    system("bin/rails generate controller Sessions new create destroy")
  end
end

# Task to bootstrap rails-app if it doesn't exist
desc "Create a minimal Rails application for testing if rails-app doesn't exist"
task :bootstrap_rails_app do
  rails_app_dir = File.expand_path("rails-app", __dir__)

  if File.directory?(rails_app_dir)
    puts "Rails application already exists at #{rails_app_dir}"

    # Even if it exists, make sure the database is migrated
    puts "Ensuring database is migrated..."
    safe_rails_command(rails_app_dir, "bin/rails db:migrate RAILS_ENV=development")
    safe_rails_command(rails_app_dir, "bin/rails db:migrate RAILS_ENV=test")
  else
    puts "Creating Rails application at #{rails_app_dir}..."

    # Check if Rails is installed
    unless system("gem list rails -i")
      puts "Installing Rails..."
      system("gem install rails")
    end

    # Create a new Rails application with minimal sensible flags
    system("rails new #{rails_app_dir} --skip-git")

    # Add the clavis gem to the Gemfile
    gemfile_path = File.join(rails_app_dir, "Gemfile")

    # Read the current Gemfile
    gemfile_content = File.read(gemfile_path)

    # Add clavis with path to local directory
    unless gemfile_content.include?("gem \"clavis\"")
      puts "Adding clavis gem to Gemfile..."
      gem_line = "gem \"clavis\", path: \"../.\""

      # Append to Gemfile
      File.open(gemfile_path, "a") do |f|
        f.puts "\n# Add local Clavis gem for testing"
        f.puts gem_line
      end
    end

    Dir.chdir(rails_app_dir) do
      puts "Installing dependencies..."
      system("bundle install")

      # Fix bootsnap issue
      fix_bootsnap_issue

      # Fix asset configuration if needed
      assets_initializer = "config/initializers/assets.rb"
      if File.exist?(assets_initializer)
        puts "Checking assets configuration..."
        assets_content = File.read(assets_initializer)
        if assets_content.include?("Rails.application.config.assets") &&
           !system("bin/rails runner 'Rails.application.config.respond_to?(:assets)'")
          puts "Fixing assets configuration..."
          fixed_content = assets_content.gsub(/Rails\.application\.config\.assets.*$/,
                                              "# Assets configuration disabled for testing")
          File.write(assets_initializer, fixed_content)
        end
      end
    end

    # Set up authentication
    setup_rails_authentication(rails_app_dir, gemfile_content)

    # Use safe_rails_command for migrations
    safe_rails_command(rails_app_dir, "bin/rails db:migrate RAILS_ENV=development")
    safe_rails_command(rails_app_dir, "bin/rails db:migrate RAILS_ENV=test")

    # Update User model with has_secure_password
    update_user_model(rails_app_dir)

    puts "Rails application created successfully with authentication!"
  end
end

# Tasks for the dummy Rails app
namespace :dummy do
  desc "Prepare the dummy Rails app for testing"
  task prepare: :environment do
    app_path = File.expand_path("spec/dummy", __dir__)

    # Ensure the db directory exists
    FileUtils.mkdir_p(File.join(app_path, "db"))

    # Set up environment
    ENV["RAILS_ENV"] = "test"

    # Make sure we can load ActiveRecord
    require "active_record"

    # Configure ActiveRecord for in-memory SQLite
    ActiveRecord::Base.establish_connection adapter: "sqlite3", database: ":memory:"

    # Load the schema
    ActiveRecord::Schema.verbose = false
    load File.expand_path("spec/dummy/db/schema.rb", __dir__)

    Rails.logger.debug "Dummy Rails app prepared successfully!"
  end

  desc "Run RSpec tests with the dummy Rails app"
  task tests: :prepare do
    ENV["RAILS_ENV"] = "test"
    Rake::Task["spec"].invoke
  end
end

# Task to cleanup the dummy Rails app
task clean: :environment do
  app_path = File.expand_path("spec/dummy", __dir__)
  db_path = File.join(app_path, "db", "test.sqlite3")
  FileUtils.rm_f(db_path)
end

begin
  require "rubocop/rake_task"
  RuboCop::RakeTask.new
rescue LoadError
  desc "Run RuboCop"
  task rubocop: :environment do
    abort "RuboCop is not available. Run 'bundle install' first."
  end
end

begin
  require "brakeman"
  desc "Run Brakeman"
  task brakeman: :environment do
    Brakeman.run(app_path: ".")
  end
rescue LoadError
  desc "Run Brakeman"
  task brakeman: :environment do
    abort "Brakeman is not available. Run 'bundle install' first."
  end
end

desc "Run all CI checks"
task ci: %i[rubocop all_tests brakeman]
