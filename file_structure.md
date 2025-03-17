# Clavis - Proposed File Structure

```
clavis/
├── .github/                       # GitHub workflows and templates
├── bin/                           # Executable files
│   ├── console                    # Interactive console for development
│   └── setup                      # Setup script for development
├── lib/                           # Main code directory
│   ├── clavis.rb                  # Main entry point
│   ├── clavis/                    # Core library files
│   │   ├── version.rb             # Version information
│   │   ├── configuration.rb       # Configuration management
│   │   ├── errors.rb              # Custom error classes
│   │   ├── engine.rb              # Rails engine definition
│   │   ├── railtie.rb             # Rails integration
│   │   ├── utils/                 # Utility modules
│   │   │   ├── secure_token.rb    # Token generation utilities
│   │   │   ├── uri_helper.rb      # URI manipulation utilities
│   │   │   └── http_client.rb     # Faraday wrapper
│   │   ├── models/                # Model-related code
│   │   │   └── concerns/          # Model concerns
│   │   │       └── oauth_authenticatable.rb  # User model concern
│   │   ├── controllers/           # Controller-related code
│   │   │   └── concerns/          # Controller concerns
│   │   │       └── authentication.rb  # Authentication controller concern
│   │   ├── providers/             # Provider implementations
│   │   │   ├── base.rb            # Abstract provider base class
│   │   │   ├── google.rb          # Google provider implementation
│   │   │   ├── github.rb          # GitHub provider implementation
│   │   │   ├── apple.rb           # Apple provider implementation
│   │   │   ├── facebook.rb        # Facebook provider implementation
│   │   │   └── microsoft.rb       # Microsoft provider implementation
│   │   ├── view_helpers.rb        # View helper methods
│   │   └── auth_hash.rb           # Auth hash standardization
│   ├── generators/                # Generator classes
│   │   └── clavis/                # Namespace for generators
│   │       ├── install_generator.rb   # Main installation generator
│   │       ├── controllers_generator.rb # Controller generator
│   │       ├── views_generator.rb  # Views generator
│   │       └── templates/          # Templates for generators
│   │           ├── initializer.rb  # Initializer template
│   │           ├── migration.rb    # Migration template
│   │           ├── auth_controller.rb # Controller template
│   │           ├── sessions_controller.rb # Example sessions controller
│   │           └── views/          # View templates
│   │               ├── auth/       # Auth controller views
│   │               └── providers/  # Provider-specific partials
│   │                   └── _button.html.erb # Button template
│   └── assets/                    # Asset files
│       ├── images/                # Image assets
│       │   └── clavis/            # Namespace for images
│       │       └── providers/     # Provider logos
│       │           ├── google.svg # Google logo
│       │           ├── github.svg # GitHub logo
│       │           └── ...        # Other provider logos
│       └── stylesheets/           # CSS/SCSS files
│           └── clavis/            # Namespace for stylesheets
│               ├── buttons.css    # Button styles
│               └── providers.css  # Provider-specific styles
├── spec/                          # RSpec tests
│   ├── clavis_spec.rb             # Main spec file
│   ├── spec_helper.rb             # Spec configuration
│   ├── configuration_spec.rb      # Configuration tests
│   ├── providers/                 # Provider tests
│   │   ├── base_spec.rb           # Base provider tests
│   │   ├── google_spec.rb         # Google provider tests
│   │   └── ...                    # Other provider tests
│   ├── controllers/               # Controller tests
│   │   └── concerns/              # Controller concern tests
│   │       └── authentication_spec.rb # Authentication concern tests
│   ├── models/                    # Model tests
│   │   └── concerns/              # Model concern tests
│   │       └── oauth_authenticatable_spec.rb # User concern tests
│   ├── view_helpers_spec.rb       # View helper tests
│   ├── generators/                # Generator tests
│   │   └── install_generator_spec.rb # Install generator tests
│   ├── integration/               # Integration tests
│   │   ├── authorization_flow_spec.rb # Authorization flow tests
│   │   └── token_exchange_spec.rb # Token exchange tests
│   └── fixtures/                  # Test fixtures
│       └── auth_responses/        # Sample auth responses
│           ├── google.json        # Google auth response
│           └── ...                # Other provider responses
├── .gitignore                     # Git ignore file
├── .rspec                         # RSpec configuration
├── .rubocop.yml                   # RuboCop configuration
├── Gemfile                        # Gem dependencies
├── LICENSE.txt                    # License file
├── README.md                      # README file
├── CHANGELOG.md                   # Changelog
├── Rakefile                       # Rake tasks
└── clavis.gemspec                 # Gem specification
```

## Architecture Overview

The Clavis gem follows a modular, object-oriented architecture with clear separation of concerns:

### Core Components

1. **Configuration**
   - Centralized configuration system
   - Provider settings management
   - Default option handling

2. **Provider System**
   - Abstract base class with common logic
   - Individual provider implementations that extend the base
   - Provider-specific quirks isolated to their respective classes

3. **Authentication Flow**
   - Clean separation between authorization and token exchange
   - Standardized auth hash format across providers
   - Secure token handling and validation

4. **Rails Integration**
   - Rails engine for routes and assets
   - Controller concerns for authentication logic
   - Model concerns for user management
   - View helpers for UI components

### Design Principles

1. **Single Responsibility Principle**
   - Each class has a singular, well-defined purpose
   - Concerns are used to share behavior across classes

2. **Open/Closed Principle**
   - Core architecture is open for extension but closed for modification
   - New providers can be added without changing existing code

3. **Dependency Inversion**
   - High-level modules don't depend on low-level implementations
   - All components depend on abstractions

4. **Composition Over Inheritance**
   - Limit inheritance chains to where they make sense (providers)
   - Use composition and concerns for shared functionality

5. **Convention Over Configuration**
   - Follow Rails conventions where appropriate
   - Sensible defaults with clear override mechanisms

## Key Class Relationships

```
Configuration ─┐
               │
Provider::Base ┼─── Provider::Google
               │     Provider::GitHub
               │     Provider::Apple
               │     ...
               │
Controllers::Concerns::Authentication ───┐
                                         ├─── ApplicationController
Models::Concerns::OauthAuthenticatable ──┘
```

## Module Structure

```ruby
module Clavis
  # Core functionality
  class Configuration
  end
  
  class Error < StandardError
  end
  
  # Provider handling
  module Providers
    class Base
    end
    
    class Google < Base
    end
    
    # Other providers...
  end
  
  # Rails integration
  module Controllers
    module Concerns
      module Authentication
      end
    end
  end
  
  module Models
    module Concerns
      module OauthAuthenticatable
      end
    end
  end
  
  module ViewHelpers
  end
  
  # Rails engine
  class Engine < ::Rails::Engine
  end
end
```

## Testing Strategy

1. **Unit Tests**
   - Individual components tested in isolation
   - Mocked dependencies
   - Focus on correctness of logic

2. **Integration Tests**
   - End-to-end flows
   - Provider interactions (with stubbed HTTP)
   - Rails integration

3. **Security Tests**
   - Token validation
   - CSRF protection
   - State parameter security 