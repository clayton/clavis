# frozen_string_literal: true

module Clavis
  class OauthIdentity < ApplicationRecord
    self.table_name = "clavis_oauth_identities"

    belongs_to :authenticatable, polymorphic: true

    serialize :auth_data, JSON

    include Clavis::Models::Concerns::OauthIdentity
  end
end
