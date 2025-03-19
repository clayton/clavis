# Changelog

All notable changes to this project will be documented in this file.

## [0.6.8] - 2024-03-20

### Fixed
- Fixed route conflict issues in engine mounting
- Improved route handling with proper tracking of registered routes
- Replaced global variables with Engine instance variables for route tracking
- Fixed bcrypt dependency issues in CI test Rails app
- Updated Rails test app to use the built-in Rails 8 authentication generator
- Removed oauth_button legacy alias in favor of clavis_oauth_button

## [0.6.7] - 2024-03-19

### Fixed
- Fixed bcrypt dependency for test Rails application in CI
- Improved dependency management in test environment
- Added explicit bcrypt installation to prevent authentication failures

## [0.6.6] - 2024-03-19

### Fixed
- Fixed CI issues with Rails application testing
- Improved test suite reliability with better error handling
- Enhanced Rails generator tests to handle bootsnap dependency
- Added automatic fixes for common Rails initialization issues

## [0.6.0] - 2024-05-10

### Added
- Added `oauth_user?` method to `OauthAuthenticatable` concern to easily check if a user has any OAuth identities
- Added automatic route setup to simplify integration (no need to manually define routes anymore)

### Changed
- Enhanced the built-in AuthController to handle OAuth flows without requiring a custom controller
- Improved documentation on route setup and OAuth integration
- Added Quick Start guides to README and LLMs documentation

## [0.5.2] - 2023-03-18

### Changed
- Removed unnecessary bigdecimal and mutex_m dependencies

## [0.5.1] - 2023-03-18

### Fixed
- Updated release workflow to use Ruby 3.3
- Fixed RuboCop target Ruby version to match required version

## [0.5.0] - 2023-03-18

### Changed
- Updated to require Rails 8.0 only
- Updated minimum Ruby version to 3.3.0
- Removed support for Rails 7.x
- Simplified serialization code now that we only support Rails 8.0+

## [0.3.4] - 2023-03-18

### Fixed
- Resolved compatibility issues with Rails 8 eager loading
- Fixed timezone handling in OauthIdentity expirations
- Added test coverage for Rails 8.0 and Ruby 3.4

## [0.3.1] - 2023-03-19

### Added
- Improved provider buttons with proper branding according to each provider's guidelines
- Enhanced SVG icons for all supported providers with official logos and colors
- Added branded provider button styles to match each provider's requirements
- Updated documentation with information about the branded buttons

### Changed
- Redesigned button CSS to provide a more professional look and feel
- Refined the display of button icons and text for better alignment
- Updated the README to clarify information about button styling options

## [0.3.0] - 2023-03-18

### Added
- Standardized user information extraction from all OAuth providers
- Added methods to access email, name, and avatar URL from any provider
- Helper methods on User model via OauthAuthenticatable: `oauth_email`, `oauth_name`, and `oauth_avatar_url`
- Storage of standardized user info in the auth_data JSON field

## [0.2.3] - 2023-03-25

### Fixed
- Added missing `process_callback` method to Provider::Base class for handling OAuth callbacks
- Fixed authorization code validation to handle special characters in Google's OAuth codes
- Improved JSON parsing to handle both string and hash response bodies from OAuth providers
- Made token and userinfo validation more permissive to work with various OAuth provider responses
- Added comprehensive integration tests for the OAuth callback flow

## [0.2.2] - 2023-03-19

### Fixed
- Added `allow_other_host: true` to OAuth redirects to fix `ActionController::Redirecting::UnsafeRedirectError` errors in Rails 7
- This ensures compatibility with stricter cross-origin redirect security in newer Rails versions

## [0.2.1] - 2023-03-18

### Changed
- Namespaced view helper methods to prevent conflicts with Rails form helpers
  - `oauth_button` -> `clavis_oauth_button`
  - `provider_svg` -> `clavis_provider_svg`
- Made view helper inclusion configurable through `config.view_helpers_auto_include` option
- Updated documentation to reflect the new helper naming and inclusion options
- Engine configuration now defaults to automatically include view helpers

### Fixed
- Conflicts between Clavis view helpers and Rails form helpers when using `form_with`

## [0.2.0] - 2023-03-17

### Fixed
- Module name inconsistency between `Clavis::Models::OauthAuthenticatable` and `Clavis::Models::Concerns::OauthAuthenticatable`