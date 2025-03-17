# Clavis

Clavis is a Ruby gem that provides an easy-to-use implementation of OIDC (OpenID Connect) and OAuth2 functionality for Rails applications. It focuses on simplifying the "Sign in with ____" experience while adhering to relevant security standards and best practices.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'clavis'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install clavis
```

## Usage

### Configuration

Configure Clavis in an initializer:

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

### Controller Integration

Include the authentication concern in your controller:

```ruby
# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController
  include Clavis::Controllers::Concerns::Authentication
  
  def create_from_oauth
    oauth_callback do |user, auth_hash|
      # Sign the user in
      session[:user_id] = user.id
      redirect_to root_path, notice: "Signed in with #{auth_hash[:provider].to_s.capitalize}!"
    end
  rescue Clavis::InvalidState
    redirect_to login_path, alert: "Authentication failed (invalid state)"
  rescue Clavis::AuthorizationDenied
    redirect_to login_path, alert: "You cancelled the authentication"
  rescue Clavis::TokenError => e
    Rails.logger.error("Token error: #{e.message}")
    redirect_to login_path, alert: "Authentication failed"
  end
end
```

### User Model Integration

Include the OAuth authenticatable concern in your User model:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Clavis::Models::Concerns::OauthAuthenticatable
  
  # Customize user creation if needed
  def self.find_for_oauth(auth_hash)
    super do |user, auth|
      user.name = auth[:info][:name]
      user.avatar_url = auth[:info][:image]
    end
  end
end
```

### View Integration

Include the view helpers in your application helper:

```ruby
# app/helpers/application_helper.rb
module ApplicationHelper
  include Clavis::ViewHelpers
end
```

Then use the helpers in your views:

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
  <%= oauth_button :google %>
  <%= oauth_button :github %>
  <%= oauth_button :apple %>
</div>
```

### Routes

Add the necessary routes to your application:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  # OAuth routes
  get '/auth/:provider', to: 'sessions#oauth_authorize', as: :auth_authorize
  get '/auth/:provider/callback', to: 'sessions#create_from_oauth'
  
  # Other routes...
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/clayton/clavis. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/clayton/clavis/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Clavis project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/clayton/clavis/blob/main/CODE_OF_CONDUCT.md).
