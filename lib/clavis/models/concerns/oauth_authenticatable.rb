# frozen_string_literal: true

require "active_support/concern"

module Clavis
  module Models
    module Concerns
      # This module adds OAuth authentication capabilities to a model
      # It's typically included in the User model
      module OauthAuthenticatable
        extend ActiveSupport::Concern

        included do
          # Setup relationships
          has_many :oauth_identities,
                   class_name: "Clavis::OauthIdentity",
                   dependent: :destroy
        end

        # Get the primary OAuth identity for this user
        #
        # @return [Clavis::OauthIdentity, nil] The primary OAuth identity
        def oauth_identity
          oauth_identities.first
        end

        # Determines if this user was created via OAuth
        #
        # @return [Boolean] True if the user has any OAuth identities
        def oauth_user?
          oauth_identities.exists?
        end

        # Get the identity for a specific provider
        #
        # @param provider [String, Symbol] The provider name
        # @return [Clavis::OauthIdentity, nil] The OAuth identity for the provider or nil
        def oauth_identity_for(provider)
          oauth_identities.find_by(provider: provider)
        end

        # Get the email from the OAuth identity
        #
        # @return [String, nil] The email from the OAuth identity or nil
        def oauth_email
          oauth_identity&.auth_data&.dig("email")
        end

        # Get the name from the OAuth identity
        #
        # @return [String, nil] The name from the OAuth identity or nil
        def oauth_name
          oauth_identity&.auth_data&.dig("name")
        end

        # Get the profile picture URL from the OAuth identity
        #
        # @return [String, nil] The profile picture URL from the OAuth identity or nil
        def oauth_avatar_url
          oauth_identity&.auth_data&.dig("image")
        end

        # Get the access token for the primary identity
        #
        # @return [String, nil] The access token or nil
        def oauth_token
          oauth_identity&.token
        end

        # Get the refresh token for the primary identity
        #
        # @return [String, nil] The refresh token or nil
        def oauth_refresh_token
          oauth_identity&.refresh_token
        end

        # Check if the token for the primary identity has expired
        #
        # @return [Boolean] True if the token has expired, false otherwise or if expires_at is nil
        def oauth_token_expired?
          return false unless oauth_identity&.expires_at

          # Convert to Time object if it's an Integer
          expires_at = if oauth_identity.expires_at.is_a?(Integer)
                         Time.at(oauth_identity.expires_at)
                       else
                         oauth_identity.expires_at
                       end
          expires_at < Time.now
        end

        # Refresh the access token for the primary identity
        #
        # @return [String, nil] The new access token or nil if refresh failed or not supported
        def refresh_oauth_token
          return nil unless oauth_identity&.refresh_token.present?

          provider = oauth_identity.provider
          provider_instance = Clavis.provider(provider)
          return nil unless provider_instance.respond_to?(:refresh_token)

          # Refresh the token
          new_tokens = provider_instance.refresh_token(oauth_identity.refresh_token)

          # Update the identity with the new tokens
          oauth_identity.token = new_tokens[:token]
          oauth_identity.refresh_token = new_tokens[:refresh_token] if new_tokens[:refresh_token].present?
          oauth_identity.expires_at = new_tokens[:expires_at] if new_tokens[:expires_at].present?
          oauth_identity.save!

          # Return the new token
          oauth_identity.token
        end
      end
    end
  end
end
