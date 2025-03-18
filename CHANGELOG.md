# Changelog

All notable changes to this project will be documented in this file.

## [0.2.2] - 2023-03-19

### Fixed
- Added `allow_other_host: true` to OAuth redirects to fix `ActionController::Redirecting::UnsafeRedirectError` errors in Rails 7
- This ensures compatibility with stricter cross-origin redirect security in newer Rails versions

## [0.2.1] - 2023-03-18

### Changed
- Namespaced view helper methods to prevent conflicts with Rails form helpers
  - `oauth_button` -> `clavis_oauth_button` (with legacy alias)
  - `provider_svg` -> `clavis_provider_svg` (with legacy alias)
- Made view helper inclusion configurable through `config.view_helpers_auto_include` option
- Updated documentation to reflect the new helper naming and inclusion options
- Engine configuration now defaults to automatically include view helpers

### Fixed
- Conflicts between Clavis view helpers and Rails form helpers when using `form_with`

## [0.2.0] - 2023-03-17

### Fixed
- Module name inconsistency between `Clavis::Models::OauthAuthenticatable` and `Clavis::Models::Concerns::OauthAuthenticatable`
- View helpers not being properly included in application helpers 
- Issues with migration generators for OAuth identities
- Documentation inconsistencies between code and examples

### Added
- Comprehensive integration guide for adding Clavis to existing applications
- Better error handling and troubleshooting guides
- Improved support for multiple authentication methods in the same application

## [0.1.1] - 2023-03-16

- Initial release
