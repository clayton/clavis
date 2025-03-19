# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

task default: :ci

# Define an environment task for Rails-dependent tasks
task :environment do
  # This is a no-op task to satisfy dependencies
  # Rails would normally provide this task
end

# Task to run Rails-dependent tests
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
  task real_generator: :environment do
    puts "Testing basic functionality in rails-app..."
    rails_app_dir = File.expand_path("rails-app", __dir__)
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

    Dir.chdir(rails_app_dir) do
      # Install dependencies
      puts "Installing dependencies in rails-app..."
      unless system("bundle install")
        puts "Error: Failed to install dependencies in rails-app"
        exit 1
      end

      # Test loading the gem
      puts "Testing if the gem can be loaded..."
      test_code = "require 'clavis'; puts 'Clavis loaded successfully! Version: ' + Clavis::VERSION"
      load_success = system("bundle exec ruby -e \"#{test_code}\"")

      unless load_success
        puts "Error: Failed to load the clavis gem in rails-app"
        exit 1
      end

      puts "Generator dependency test in rails-app passed successfully!"
    end
  end
end

# Task to run all tests
desc "Run all tests including Rails controller tests and integration tests"
task all_tests: [:spec, "test:rails", "test:real_generator"]

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
task ci: %i[all_tests rubocop brakeman]
