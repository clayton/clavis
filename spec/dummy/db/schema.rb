# frozen_string_literal: true

ActiveRecord::Schema.define(version: 20_230_315_000_000) do
  create_table "users", force: :cascade do |t|
    t.string "email", null: false
    t.string "name"
    t.string "first_name"
    t.string "last_name"
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
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
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
    t.index %w[authenticatable_type authenticatable_id], name: "index_oauth_on_authenticatable"
    t.index %w[provider uid], name: "index_oauth_on_provider_and_uid"
  end
end
