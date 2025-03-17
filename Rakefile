# frozen_string_literal: true

require "bundler/gem_tasks"

begin
  require "rspec/core/rake_task"
  RSpec::Core::RakeTask.new(:spec)
rescue LoadError
  desc "Run specs"
  task :spec do
    abort "RSpec is not available. Run 'bundle install' first."
  end
end

begin
  require "rubocop/rake_task"
  RuboCop::RakeTask.new
rescue LoadError
  desc "Run RuboCop"
  task :rubocop do
    abort "RuboCop is not available. Run 'bundle install' first."
  end
end

# Add a brakeman task
desc "Run Brakeman security scan"
task :brakeman do
  require "brakeman"
  Brakeman.run app_path: ".", output_files: ["brakeman.html"], quiet: true, print_report: true, exit_on_warn: false
rescue LoadError
  abort "Brakeman not installed. Run `gem install brakeman`."
end

# Task to run all CI checks
desc "Run all CI checks"
task ci: %i[spec rubocop brakeman]

# Default task
task default: %i[spec rubocop]
