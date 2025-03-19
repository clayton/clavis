# frozen_string_literal: true

class AddOauthToUsers < ActiveRecord::Migration[8.0]
  def change
    # Skip if any of these columns already exist
    return if column_exists?(:users, :provider) || column_exists?(:users, :uid)

    add_column :users, :provider, :string
    add_column :users, :uid, :string
    add_column :users, :oauth_token, :string
    add_column :users, :oauth_expires_at, :datetime
    add_column :users, :oauth_refresh_token, :string
    add_column :users, :oauth_avatar_url, :string

    add_index :users, %i[provider uid], unique: true
  end
end
