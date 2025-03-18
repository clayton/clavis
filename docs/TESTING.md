# Clavis Testing Guide

This document explains how to run the test matrix locally to ensure compatibility with different Ruby and Rails versions.

## Test Matrix

Clavis is tested against the following combinations:

| Ruby Version | Rails Version | Gemfile |
|--------------|---------------|---------|
| 3.0.6        | 7.0           | gemfiles/rails_70.gemfile |
| 3.2.3        | 7.1           | gemfiles/rails_71.gemfile |
| 3.3.0        | 7.2           | gemfiles/rails_72.gemfile |
| 3.3.0        | 8.0           | gemfiles/rails_80.gemfile |
| 3.4.1        | 8.0           | gemfiles/rails_80.gemfile |

## Using the matrix_test Script

The `bin/matrix_test` script allows you to run tests with specific Ruby and Rails combinations or the entire matrix:

### To run a specific combination:

```bash
# Format: bin/matrix_test <ruby_version> <gemfile>
bin/matrix_test 3.4.1 gemfiles/rails_80.gemfile
```

### To run all matrix combinations:

```bash
bin/matrix_test all
```

Note: You need to have all the Ruby versions installed via rbenv to use this script.

## Using Act to Test GitHub Actions Locally

You can also use [act](https://github.com/nektos/act) to run the GitHub Actions matrix locally:

1. **Install act**:
   ```bash
   brew install act
   ```

2. **Run the CI workflow**:
   ```bash
   act -W .github/workflows/ci_local.yml
   ```

3. **Run a specific job**:
   ```bash
   act -W .github/workflows/ci_local.yml -j test
   ```

4. **Run with specific matrix combinations**:
   ```bash
   # You can specify matrix values to filter the jobs
   act -W .github/workflows/ci_local.yml -j test --matrix ruby-version:3.4.1
   ```

## Tips for Troubleshooting

1. If you encounter issues with a specific Rails version, you can focus your testing on that version first:
   ```bash
   bin/matrix_test 3.4.1 gemfiles/rails_80.gemfile
   ```

2. If a test fails only in the GitHub CI but works locally, use act to reproduce the CI environment.

3. To debug test failures in a specific Rails environment, you can set the Gemfile manually and add debugging output:
   ```bash
   BUNDLE_GEMFILE=gemfiles/rails_80.gemfile bundle exec rspec spec/failing_spec.rb -f d
   ```

4. Remember to run RuboCop before pushing changes:
   ```bash
   bundle exec rubocop -A
   ``` 