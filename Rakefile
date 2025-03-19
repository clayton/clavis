# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

task default: :spec

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
end

# Task to run all tests
desc "Run all tests including Rails controller tests and integration tests"
task all_tests: [:spec, "test:rails"]

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
task ci: %i[spec rubocop brakeman]
