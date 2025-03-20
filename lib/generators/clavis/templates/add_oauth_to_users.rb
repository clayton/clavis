# frozen_string_literal: true

class AddOauthToUsers < ActiveRecord::Migration[<%= Rails::VERSION::MAJOR %>.<%= Rails::VERSION::MINOR %>]
  def change
    # Add oauth_user flag to identify users created through OAuth
    # This helps with password validation for has_secure_password
    add_column :users, :oauth_user, :boolean, default: false
    
    # These fields are added by default for better OAuth integration
    # You can comment out any fields you don't want to use
    
    # Cache the avatar URL from OAuth for quicker access
    add_column :users, :avatar_url, :string, null: true

    # Track when the user last authenticated via OAuth
    add_column :users, :last_oauth_login_at, :datetime, null: true
    
    # Track which provider was most recently used
    add_column :users, :last_oauth_provider, :string, null: true
    
    # Note: All OAuth identity information (tokens, credentials, etc.) is 
    # stored in the clavis_oauth_identities table, not directly on the User.
    
    # If you have existing provider/uid columns, uncomment this to remove them:
    remove_column :users, :provider, :string
    remove_column :users, :uid, :string
  end
end
