# Clavis Upgrade Guide

## Upgrading to 0.2.0 from 0.1.x

Version 0.2.0 brings several important fixes and improvements to the Clavis gem, focusing on better documentation, improved compatibility with existing Rails applications, and bug fixes for various integration issues.

### Key Changes

1. **Module Alias Consistency**:
   - The module `Clavis::Models::OauthAuthenticatable` is now properly aliased to `Clavis::Models::Concerns::OauthAuthenticatable`
   - This means either reference can be used in your application code: `include Clavis::Models::OauthAuthenticatable` or `include Clavis::Models::Concerns::OauthAuthenticatable`

2. **View Helper Integration**:
   - Improved automatic inclusion of view helpers in Rails applications
   - Fixed issues with helper availability in `ApplicationHelper`
   - View helpers like `oauth_button` should now work out of the box

3. **Installation Generator Improvements**:
   - Updated the `clavis:install` generator to properly handle the creation of OAuth identity tables
   - Fixed issues with duplicate migrations
   - Added better support for integrating with existing User models

4. **Documentation Updates**:
   - Added comprehensive guide for integrating with existing authentication systems
   - Corrected inconsistencies between code examples and actual implementations
   - Updated installation and configuration guidance

### Migration Steps

**For most users, no changes are required**. The improvements in 0.2.0 are backward compatible.

If you encountered any of the specific issues addressed in this release, upgrade to 0.2.0 and follow these steps:

1. Update your Gemfile:
   ```ruby
   gem 'clavis', '~> 0.2.0'
   ```

2. Run bundle install:
   ```bash
   bundle install
   ```

3. If you've manually implemented workarounds for any of the fixed issues, you can now remove them.

4. If you're integrating with an existing application, refer to the new integration guide at `/docs/integration.md` for detailed instructions.

### New Documentation

- `docs/integration.md` - Guide for integrating Clavis with existing authentication systems
- Updated README with clearer instructions and example code
- Improved error handling documentation

### Known Issues

- Rails 7.1+ and Ruby 3.4+ compatibility testing is ongoing
- Full test suite coverage requires a Rails environment for some specs 