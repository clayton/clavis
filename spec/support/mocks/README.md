# Clavis Test Mocks

This directory contains mock implementations of key Clavis classes that are used in testing.

## Purpose

These mocks allow us to test Clavis functionality without requiring a full Rails application
or ActiveRecord database. They provide lightweight implementations of core functionality
that can be easily controlled and verified in tests.

## Available Mocks

- `oauth_identity.rb`: Mock implementation of the `Clavis::OauthIdentity` class, which
  normally requires ActiveRecord.
  
- `token_storage.rb`: Mock implementation of the `Clavis::Security::TokenStorage` module,
  which handles encryption and decryption of tokens.

## Usage

These mocks are automatically loaded by the test suite before loading the actual Clavis
gem, allowing them to take precedence over the real implementations. This is handled
by the loading order in `spec_helper.rb`. 