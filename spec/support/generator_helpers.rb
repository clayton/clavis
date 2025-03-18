# frozen_string_literal: true

# This file contains helper methods for testing Rails generators
# It will be loaded automatically when running specs with type: :generator

require "generator_spec/test_case"
require "rails/generators/base"
require "rails/generators/active_record"
require "rails/generators/actions"

module GeneratorHelpers
  # Add assertion methods based on assertions from Rails::Generators::TestCase
  def assert_file(relative, *contents)
    absolute = File.expand_path(relative, destination_root)
    expect(File.exist?(absolute)).to be true

    contents.each do |content|
      expect(File.read(absolute)).to match(content)
    end

    yield File.read(absolute) if block_given?
  end

  def assert_migration(relative, *contents, &)
    absolute = migration_file_path(relative)
    assert_file(absolute, *contents, &)
  end

  def assert_no_migration(relative)
    absolute = migration_file_path(relative)
    expect(File.exist?(absolute)).to be false
  end

  def migration_file_path(relative)
    dirname = File.dirname(relative)
    basename = File.basename(relative)
    Dir.glob("#{destination_root}/#{dirname}/[0-9]*_#{basename}").first
  end

  def capture(stream)
    stream = stream.to_s
    captured_stream = Tempfile.new(stream)
    orig_stream = $stdout
    $stdout = captured_stream
    yield
    captured_stream.rewind
    captured_stream.read
  ensure
    captured_stream.close
    $stdout = orig_stream
  end

  def prepare_generator_test
    prepare_destination

    # Create necessary directories
    FileUtils.mkdir_p("#{destination_root}/config/initializers")
    FileUtils.mkdir_p("#{destination_root}/db/migrate")
    FileUtils.mkdir_p("#{destination_root}/app/models")

    # Create a dummy ApplicationRecord class
    File.write("#{destination_root}/app/models/application_record.rb", <<~RUBY)
      class ApplicationRecord < ActiveRecord::Base
        self.abstract_class = true
      end
    RUBY
  end
end

# If Rails is not defined properly for generators
unless defined?(Rails::Generators::Base)
  module Rails
    module Generators
      class Base
        include Rails::Generators::Actions if defined?(Rails::Generators::Actions)
      end
    end
  end
end

RSpec.configure do |config|
  config.include GeneratorHelpers, type: :generator

  config.before(:each, type: :generator) do
    # Make sure we include GeneratorSpec::TestCase
    self.class.include GeneratorSpec::TestCase
    prepare_generator_test
  end
end
