# frozen_string_literal: true

require "active_support/concern"

module Clavis
  module Models
    module Concerns
      module OauthAuthenticatable
        extend ActiveSupport::Concern

        included do
          has_many :oauth_identities, class_name: "Clavis::OauthIdentity", dependent: :destroy
        end

        class_methods do
          def find_for_oauth(auth_hash)
            # Find or create the identity
            identity = Clavis::OauthIdentity.find_or_initialize_by(
              provider: auth_hash[:provider],
              uid: auth_hash[:uid]
            )

            # If the identity exists but is not associated with a user, find or create the user
            if identity.new_record? || identity.user.nil?
              user = find_or_create_user_from_oauth(auth_hash)
              identity.user = user
            end

            # Update the identity with the latest auth data
            identity.auth_data = auth_hash[:info]
            identity.token = auth_hash[:credentials][:token]
            identity.refresh_token = auth_hash[:credentials][:refresh_token]
            identity.expires_at = if auth_hash[:credentials][:expires_at]
                                    Time.at(auth_hash[:credentials][:expires_at])
                                  end
            identity.save!

            # Yield to the block if given, to allow customization
            yield(identity.user, auth_hash) if block_given?

            identity.user.save! if identity.user.changed?
            identity.user
          end

          private

          def find_or_create_user_from_oauth(auth_hash)
            # Try to find an existing user by email
            email = auth_hash[:info][:email]
            user = email.present? ? find_by(email: email) : nil

            # If no user found, create a new one
            user ||= new
            user.email = email if email.present? && user.respond_to?(:email=)
            user
          end
        end

        # Instance methods

        def oauth_identity_for(provider)
          oauth_identities.find_by(provider: provider.to_s)
        end

        def connected_to?(provider)
          oauth_identity_for(provider).present?
        end

        def refresh_oauth_token(provider)
          identity = oauth_identity_for(provider)
          return nil unless identity&.refresh_token.present?

          begin
            provider_instance = Clavis.provider(
              provider.to_sym,
              redirect_uri: Clavis.configuration.providers.dig(provider.to_sym, :redirect_uri)
            )

            new_tokens = provider_instance.refresh_token(identity.refresh_token)

            identity.update(
              token: new_tokens[:access_token],
              refresh_token: new_tokens[:refresh_token] || identity.refresh_token,
              expires_at: new_tokens[:expires_at] ? Time.at(new_tokens[:expires_at]) : nil
            )

            identity.token
          rescue Clavis::UnsupportedOperation => e
            Rails.logger.info("Token refresh not supported for #{provider}: #{e.message}")
            identity.token
          rescue Clavis::Error => e
            Rails.logger.error("Failed to refresh token for #{provider}: #{e.message}")
            nil
          end
        end

        def ensure_fresh_oauth_token(provider)
          identity = oauth_identity_for(provider)
          return nil unless identity.present?

          if identity.token_expired?
            refresh_oauth_token(provider)
          else
            identity.token
          end
        end
      end
    end
  end
end
