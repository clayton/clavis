# Clavis Test Support

This directory contains support files for testing the Clavis gem.

## Directory Structure

- `mocks/`: Contains mock implementations of Clavis classes for testing without Rails/ActiveRecord
- `generator_helpers.rb`: Provides helper methods for testing Rails generators (loaded only for generator tests)

## Loading Order

Support files are loaded in a specific order:

1. Mock classes are loaded first to ensure they take precedence over real implementations
2. The Clavis gem is loaded
3. General support files are loaded
4. Specialized support files (like generator helpers) are loaded on demand based on test tags

This loading order is managed in `spec_helper.rb`. 