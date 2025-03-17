# frozen_string_literal: true

require "active_support/concern"

module Clavis
  module Models
    module Concerns
      module OauthAuthenticatable
        extend ActiveSupport::Concern

        class_methods do
          def find_for_oauth(auth_hash)
            user = find_by(provider: auth_hash[:provider], uid: auth_hash[:uid])

            unless user
              user = new(
                provider: auth_hash[:provider],
                uid: auth_hash[:uid],
                email: auth_hash[:info][:email]
                # Additional fields as needed
              )

              # Allow customization via a block
              yield(user, auth_hash) if block_given?

              user.save!
            end

            # Process custom claims if configured
            if Clavis.configuration.claims_processor.respond_to?(:call)
              Clavis.configuration.claims_processor.call(auth_hash, user)
            end

            user
          end
        end
      end
    end
  end
end
