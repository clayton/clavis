# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in clavis.gemspec
gemspec

# Development dependencies
gem "brakeman", "~> 6.1"
gem "generator_spec", "~> 0.9.4"
gem "rake", "~> 13.0"
gem "rspec", "~> 3.0"
gem "rspec-rails", "~> 6.0"
gem "rubocop", "~> 1.21"

gem "ostruct", "~> 0.6.0"

gem "bcrypt" # for rails 8 authentication in our dummy app

# Development dependencies moved from gemspec
gem "capybara", "~> 3.39", group: %i[development test]
gem "sqlite3", "~> 2.1.0", group: %i[development test]

gem "rack-attack", "~> 6.7"

gem "webmock", "~> 3.25", groups: [:test, :development]

gem "simplecov", "~> 0.22.0", groups: [:test, :development]
