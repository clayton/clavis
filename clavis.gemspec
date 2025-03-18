# frozen_string_literal: true

require_relative "lib/clavis/version"

Gem::Specification.new do |spec|
  spec.name = "clavis"
  spec.version = Clavis::VERSION
  spec.authors = ["Clayton Lengel-Zigich"]
  spec.email = ["6334+clayton@users.noreply.github.com"]

  spec.summary = "A Ruby gem for OIDC and OAuth2."
  spec.description = "A Ruby gem for OIDC and OAuth2. Easily integrate with your favorite identity provider."
  spec.homepage = "https://github.com/claytonlengel/clavis"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/clayton/clavis"
  spec.metadata["changelog_uri"] = "https://github.com/clayton/clavis/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  spec.add_dependency "faraday", "~> 2.7"
  spec.add_dependency "jwt", "~> 2.7"
  spec.add_dependency "rails", "~> 8.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html

  spec.add_development_dependency "capybara"
  spec.add_development_dependency "generator_spec"
  spec.add_development_dependency "omniauth", "~> 2.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rspec-rails"
  spec.add_development_dependency "sqlite3"
end
