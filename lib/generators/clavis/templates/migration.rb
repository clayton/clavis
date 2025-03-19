# frozen_string_literal: true

class CreateClavisOauthIdentities < ActiveRecord::Migration[8.0]
  def change
    create_table :clavis_oauth_identities do |t|
      t.references :user, polymorphic: true, null: false, index: true
      t.string :provider, null: false
      t.string :uid, null: false
      t.json :auth_data
      t.string :token
      t.string :refresh_token
      t.datetime :expires_at
      t.timestamps
      
      t.index [:provider, :uid], unique: true
    end
  end
end 