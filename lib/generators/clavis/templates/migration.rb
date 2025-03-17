# frozen_string_literal: true

class AddOauthToUsers < ActiveRecord::Migration[<%= ActiveRecord::Migration.current_version %>]
  def change
    add_column :users, :provider, :string unless column_exists?(:users, :provider)
    add_column :users, :uid, :string unless column_exists?(:users, :uid)
    add_column :users, :oauth_token, :string unless column_exists?(:users, :oauth_token)
    add_column :users, :oauth_expires_at, :datetime unless column_exists?(:users, :oauth_expires_at)
    
    add_index :users, [:provider, :uid], unique: true unless index_exists?(:users, [:provider, :uid])
  end
end 