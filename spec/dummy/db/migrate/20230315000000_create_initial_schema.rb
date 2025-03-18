# frozen_string_literal: true

class CreateInitialSchema < ActiveRecord::Migration[6.1]
  def change
    create_table "users", force: :cascade do |t|
      t.string "email", null: false
      t.string "name"
      t.string "first_name"
      t.string "last_name"
      t.timestamps
      t.index ["email"], name: "index_users_on_email", unique: true
    end

    create_table "clavis_oauth_identities", force: :cascade do |t|
      t.string "provider", null: false
      t.string "uid", null: false
      t.string "token"
      t.string "refresh_token"
      t.datetime "expires_at"
      t.string "authenticatable_type", null: false
      t.integer "authenticatable_id", null: false
      t.text "auth_data"
      t.timestamps
      t.index %w[authenticatable_type authenticatable_id], name: "index_oauth_on_authenticatable"
      t.index %w[provider uid], name: "index_oauth_on_provider_and_uid"
    end
  end
end
