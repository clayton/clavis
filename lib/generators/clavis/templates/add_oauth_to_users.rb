# frozen_string_literal: true

class AddOauthToUsers < ActiveRecord::Migration<%= Rails::VERSION::MAJOR %>.<%= Rails::VERSION::MINOR %>
  def change
    # These are OPTIONAL fields for your User model that might be useful for OAuth
    # Uncomment the ones you'd like to use

    # Cache the avatar URL from OAuth for quicker access
    # add_column :users, :avatar_url, :string, null: true

    # Track when the user last authenticated via OAuth
    # add_column :users, :last_oauth_login_at, :datetime, null: true
    
    # Track which provider was most recently used
    # add_column :users, :last_oauth_provider, :string, null: true
    
    # Remember if the user is primarily an OAuth user
    # add_column :users, :oauth_user, :boolean, default: false
    
    # Note: All OAuth identity information (tokens, credentials, etc.) is 
    # stored in the clavis_oauth_identities table, not directly on the User.
  end
end
