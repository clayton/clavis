# Clavis - Implementation Plan (Revised)

## Overview

Clavis will be a Ruby gem that provides an easy-to-use implementation of OIDC (OpenID Connect) and OAuth2 functionality for Rails applications. It will focus on simplifying the "Sign in with ____" experience while adhering to relevant security standards and best practices.

## Core Requirements

1. **OIDC/OAuth2 Implementation**
   - Support for Authorization Code Flow (primary)
   - Session-based authentication integration with Rails
   - Support for major identity providers (Google, Apple, GitHub, Facebook, Microsoft)

2. **Rails Integration**
   - Idempotent generators for controllers and views
   - Individual view helpers for provider buttons with SVG icons
   - Integration with Rails 8 authentication via concerns
   - Customizable templates and styling

3. **Developer Experience**
   - Sensible defaults for quick implementation
   - Comprehensive documentation
   - Flexible configuration options
   - Configuration validation with helpful errors

## Ideal Developer Workflow

1. Developer has existing Rails 8 application with user authentication
2. They install the Clavis gem
3. They run generators to set up Clavis infrastructure
4. They add provider buttons to their existing login page
5. They include the authentication concern in their User model
6. They add provider credentials via environment variables or Rails credentials
7. It just works

## Implementation Phases

### Phase 1: Core Infrastructure (2 weeks)

1. **Set up gem structure**
   - Define module structure and namespaces
   - Set up configuration options and defaults
   - Add Faraday dependency for HTTP communications

2. **Implement OIDC/OAuth2 Core**
   - Authorization Code Flow implementation
   - Token handling and validation
   - ID token processing
   - State management for security

3. **Provider Implementations**
   - Abstract provider class
   - Implementation for Google (reference implementation)
   - Standardized approach for provider-specific quirks
   - Configuration validation logic

### Phase 2: Rails Integration (2 weeks)

1. **Rails Engine Setup**
   - Mount routes
   - Controller templates
   - Configuration integration

2. **Generators**
   - Idempotent controller generator
   - Idempotent views generator
   - Idempotent configuration generator
   - Migration generator for user model

3. **View Helpers**
   - Individual button helpers with provider validation
   - Styling helpers with customization options

### Phase 3: Additional Providers & Testing (2 weeks)

1. **Additional Provider Implementations**
   - GitHub
   - Apple
   - Facebook
   - Microsoft

2. **Testing Infrastructure**
   - Unit tests for core components
   - Integration tests for flows
   - Stubbed provider responses

3. **Documentation**
   - Usage examples
   - Configuration options
   - Customization guide

### Phase 4: Refinement & QA (1 week)

1. **Security Review**
   - Validate token handling
   - Verify state management
   - Ensure proper error handling

2. **Performance Optimization**
   - Response caching where appropriate
   - Minimize unnecessary requests

3. **Final Polish**
   - Ensure consistent styling
   - Complete documentation
   - Version 1.0.0 preparation

## Technical Architecture

### Core Components

1. **Configuration**
   ```ruby
   # lib/clavis/configuration.rb
   module Clavis
     class Configuration
       attr_accessor :providers, :default_callback_path, :default_scopes
       
       def provider_configured?(provider_name)
         providers&.key?(provider_name.to_sym) && 
           providers[provider_name.to_sym][:client_id].present? && 
           providers[provider_name.to_sym][:client_secret].present?
       end
       
       def validate_provider!(provider_name)
         raise Clavis::ProviderNotConfigured.new(provider_name) unless provider_configured?(provider_name)
       end
     end
   end
   ```

2. **Provider Base Class**
   ```ruby
   # lib/clavis/providers/base.rb
   module Clavis
     module Providers
       class Base
         attr_reader :client_id, :client_secret, :redirect_uri
         
         def initialize(config = {})
           @client_id = config[:client_id] || 
                        ENV["CLAVIS_#{provider_name.upcase}_CLIENT_ID"] || 
                        Rails.application.credentials.dig(:clavis, provider_name, :client_id)
           
           @client_secret = config[:client_secret] || 
                           ENV["CLAVIS_#{provider_name.upcase}_CLIENT_SECRET"] || 
                           Rails.application.credentials.dig(:clavis, provider_name, :client_secret)
           
           @redirect_uri = config[:redirect_uri]
           
           validate_configuration!
         end
         
         def authorize_url(state:, nonce:, scope:)
           # Build authorization URL
         end
         
         def token_exchange(code:)
           # Exchange code for tokens using Faraday
         end
         
         def parse_id_token(token)
           # Parse and validate the ID token
         end
         
         private
         
         def validate_configuration!
           raise Clavis::MissingConfiguration.new("client_id for #{provider_name}") if @client_id.blank?
           raise Clavis::MissingConfiguration.new("client_secret for #{provider_name}") if @client_secret.blank?
         end
       end
     end
   end
   ```

3. **Authentication Controller Concern**
   ```ruby
   # lib/clavis/controllers/concerns/authentication.rb
   module Clavis
     module Controllers
       module Authentication
         extend ActiveSupport::Concern
         
         def oauth_authorize
           provider = Clavis.provider(params[:provider])
           redirect_to provider.authorize_url(
             state: generate_state,
             nonce: generate_nonce,
             scope: params[:scope] || Clavis.configuration.default_scopes
           )
         end
         
         def oauth_callback
           provider = Clavis.provider(params[:provider])
           auth_hash = provider.process_callback(params[:code], session.delete(:oauth_state))
           user = find_or_create_user_from_oauth(auth_hash)
           
           # Let the application handle the user authentication
           yield(user, auth_hash) if block_given?
         end
         
         private
         
         def generate_state
           state = SecureRandom.hex(24)
           session[:oauth_state] = state
           state
         end
         
         def generate_nonce
           SecureRandom.hex(16)
         end
       end
     end
   end
   ```

4. **User Authentication Concern**
   ```ruby
   # lib/clavis/models/concerns/oauth_authenticatable.rb
   module Clavis
     module Models
       module OauthAuthenticatable
         extend ActiveSupport::Concern
         
         class_methods do
           def find_for_oauth(auth_hash)
             user = find_by(provider: auth_hash[:provider], uid: auth_hash[:uid])
             
             unless user
               user = new(
                 provider: auth_hash[:provider],
                 uid: auth_hash[:uid],
                 email: auth_hash[:info][:email],
                 # Additional fields as needed
               )
               
               # Allow customization via a block
               yield(user, auth_hash) if block_given?
               
               user.save!
             end
             
             user
           end
         end
       end
     end
   end
   ```

5. **View Helpers**
   ```ruby
   # lib/clavis/view_helpers.rb
   module Clavis
     module ViewHelpers
       def clavis_oauth_button(provider, options = {})
         # Validate provider configuration
         Clavis.configuration.validate_provider!(provider)
         
         # Render button with proper styling and SVG
         button_text = options.delete(:text) || "Sign in with #{provider.to_s.titleize}"
         button_class = "clavis-button clavis-#{provider}-button #{options.delete(:class)}"
         
         link_to auth_authorize_path(provider), class: button_class, method: :post, data: options[:data] do
           provider_svg(provider) + content_tag(:span, button_text)
         end
       rescue Clavis::ProviderNotConfigured => e
         # Return error message or comment in development/test
         if Rails.env.development? || Rails.env.test?
           content_tag(:div, "#{provider} not configured. Add client_id and client_secret.", class: 'clavis-error')
         else
           Rails.logger.error("Attempted to use unconfigured provider: #{provider}")
           nil
         end
       end
       
       def provider_svg(provider)
         # Return SVG for the provider
       end
     end
   end
   ```

### Generators

1. **Install Generator**
   ```ruby
   # lib/generators/clavis/install_generator.rb
   module Clavis
     class InstallGenerator < Rails::Generators::Base
       source_root File.expand_path("../templates", __FILE__)
       
       class_option :providers, type: :array, default: []
       
       def create_initializer
         template "initializer.rb", "config/initializers/clavis.rb"
       end
       
       def create_migration
         migration_template "migration.rb", "db/migrate/add_oauth_to_users.rb", skip: true
       end
       
       def mount_engine
         route "mount Clavis::Engine => '/auth'"
       end
       
       def create_controllers
         generate "clavis:controllers", options[:providers].join(" ")
       end
       
       def create_views
         generate "clavis:views", options[:providers].join(" ")
       end
       
       def add_user_concern
         inject_into_file "app/models/user.rb", after: "class User < ApplicationRecord\n" do
           "  include Clavis::Models::OauthAuthenticatable\n"
         end
       end
       
       def show_post_install_message
         say "\nClavis has been installed! Next steps:"
         say "1. Run migrations: rails db:migrate"
         say "2. Configure your providers in config/initializers/clavis.rb"
         say "3. Add provider buttons to your views: <%= clavis_oauth_button :google %>"
         say "\nFor more information, see the documentation at https://github.com/clayton/clavis"
       end
     end
   end
   ```

2. **Controllers Generator**
   ```ruby
   # lib/generators/clavis/controllers_generator.rb
   module Clavis
     class ControllersGenerator < Rails::Generators::Base
       source_root File.expand_path("../templates", __FILE__)
       
       argument :providers, type: :array, default: []
       
       def create_controllers
         template "auth_controller.rb", "app/controllers/clavis/auth_controller.rb"
       end
       
       def create_example_controller
         template "sessions_controller.rb", "app/controllers/clavis/sessions_controller.rb"
       end
     end
   end
   ```

3. **Views Generator**
   ```ruby
   # lib/generators/clavis/views_generator.rb
   module Clavis
     class ViewsGenerator < Rails::Generators::Base
       source_root File.expand_path("../templates", __FILE__)
       
       argument :providers, type: :array, default: []
       
       def create_views
         directory "views", "app/views/clavis"
       end
       
       def create_provider_specific_views
         providers.each do |provider|
           @provider = provider
           template "views/providers/_button.html.erb", "app/views/clavis/providers/_#{provider}_button.html.erb"
         end
       end
     end
   end
   ```

### Required Migrations

```ruby
# lib/generators/clavis/templates/migration.rb
class AddOauthToUsers < ActiveRecord::Migration[8.0]
  def change
    add_column :users, :provider, :string unless column_exists?(:users, :provider)
    add_column :users, :uid, :string unless column_exists?(:users, :uid)
    add_column :users, :oauth_token, :string unless column_exists?(:users, :oauth_token)
    add_column :users, :oauth_expires_at, :datetime unless column_exists?(:users, :oauth_expires_at)
    
    add_index :users, [:provider, :uid], unique: true unless index_exists?(:users, [:provider, :uid])
  end
end
```

## Dependencies

- **Faraday**: HTTP client library for API requests
- **JWT**: JSON Web Token implementation for token validation
- **Rails (>= 8.0)**: Framework integration

## Testing Strategy

1. **Unit Tests**
   - Test core components in isolation
   - Mock HTTP responses for predictability
   - Validate token generation/parsing

2. **Integration Tests**
   - Test full authentication flows
   - Stub provider responses
   - Verify session management

3. **Security Tests**
   - Verify CSRF protection
   - Test state parameter validation
   - Ensure proper error handling for invalid tokens

## Example Usage

### Configuration

```ruby
# config/initializers/clavis.rb
Clavis.configure do |config|
  config.providers = {
    google: {
      client_id: ENV['GOOGLE_CLIENT_ID'],
      client_secret: ENV['GOOGLE_CLIENT_SECRET'],
      redirect_uri: 'https://myapp.com/auth/google/callback'
    },
    github: {
      client_id: Rails.application.credentials.dig(:github, :client_id),
      client_secret: Rails.application.credentials.dig(:github, :client_secret),
      redirect_uri: 'https://myapp.com/auth/github/callback'
    }
  }
end
```

### User Model

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::OauthAuthenticatable
  
  # Customize user creation if needed
  def self.find_for_oauth(auth_hash)
    super do |user, auth|
      user.name = auth[:info][:name]
      user.avatar_url = auth[:info][:image]
    end
  end
end
```

### Controller

```ruby
# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController
  include Clavis::Controllers::Authentication
  
  def create_from_oauth
    oauth_callback do |user, auth_hash|
      # Sign the user in
      session[:user_id] = user.id
      redirect_to root_path, notice: "Signed in with #{auth_hash[:provider].to_s.titleize}!"
    end
  end
end
```

### View

```erb
<%# app/views/sessions/new.html.erb %>
<h1>Sign in</h1>

<%= form_with url: login_path, method: :post do |f| %>
  <div class="field">
    <%= f.label :email %>
    <%= f.email_field :email %>
  </div>
  
  <div class="field">
    <%= f.label :password %>
    <%= f.password_field :password %>
  </div>
  
  <div class="actions">
    <%= f.submit "Sign in" %>
  </div>
<% end %>

<div class="oauth-providers">
  <p>Or sign in with:</p>
  <%= clavis_oauth_button :google %>
  <%= clavis_oauth_button :github %>
  <%= clavis_oauth_button :apple %>
</div>
```

## Risk Assessment

1. **Provider API Changes**
   - Mitigation: Version-specific implementations with fallbacks
   - Regular testing against live endpoints

2. **Security Vulnerabilities**
   - Mitigation: Thorough security review
   - Follow OIDC/OAuth2 best practices strictly
   - Regular updates for security patches

3. **Rails Version Compatibility**
   - Mitigation: Clear version requirements
   - Testing against multiple Rails versions

## Future Enhancements (Post 1.0)

1. Account linking (multiple providers per user)
2. JWT support as an alternative to session-based authentication
3. Additional providers (Twitter, LinkedIn, etc.)
4. Enhanced customization options
5. Internationalization support 