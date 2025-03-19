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
          # Setup relationships and validations
          has_many :oauth_identities,
                   class_name: "Clavis::OauthIdentity",
                   dependent: :destroy
        end

        # Determines if this user was created via OAuth
        #
        # @return [Boolean] True if the user has any OAuth identities
        def oauth_user?
          oauth_identities.exists?
        end

        # Get the most recently used OAuth identity for this user
        #
        # @return [Clavis::OauthIdentity, nil] The most recent OAuth identity or nil
        def latest_oauth_identity
          oauth_identities.order(updated_at: :desc).first
        end

        # Get the identity for a specific provider
        #
        # @param provider [String, Symbol] The provider name
        # @return [Clavis::OauthIdentity, nil] The OAuth identity for the provider or nil
        def oauth_identity_for(provider)
          oauth_identities.find_by(provider: provider)
        end

        # Get the email from the most recent OAuth identity
        #
        # @return [String, nil] The email from the OAuth identity or nil
        def oauth_email(provider = nil)
          identity = provider ? oauth_identity_for(provider) : latest_oauth_identity
          identity&.auth_data&.dig("email")
        end

        # Get the name from the most recent OAuth identity
        #
        # @return [String, nil] The name from the OAuth identity or nil
        def oauth_name(provider = nil)
          identity = provider ? oauth_identity_for(provider) : latest_oauth_identity
          identity&.auth_data&.dig("name")
        end

        # Get the profile picture URL from the most recent OAuth identity
        #
        # @return [String, nil] The profile picture URL from the OAuth identity or nil
        def oauth_avatar_url(provider = nil)
          identity = provider ? oauth_identity_for(provider) : latest_oauth_identity
          identity&.auth_data&.dig("image")
        end

        # Get the access token for a specific provider
        #
        # @param provider [String, Symbol] The provider name
        # @return [String, nil] The access token or nil
        def oauth_token(provider)
          identity = oauth_identity_for(provider)
          identity&.token
        end

        # Get the refresh token for a specific provider
        #
        # @param provider [String, Symbol] The provider name
        # @return [String, nil] The refresh token or nil
        def oauth_refresh_token(provider)
          identity = oauth_identity_for(provider)
          identity&.refresh_token
        end

        # Check if the token for a specific provider has expired
        #
        # @param provider [String, Symbol] The provider name
        # @return [Boolean] True if the token has expired, false otherwise or if expires_at is nil
        def oauth_token_expired?(provider)
          identity = oauth_identity_for(provider)
          return false unless identity&.expires_at

          # Convert to Time object if it's an Integer
          expires_at = identity.expires_at.is_a?(Integer) ? Time.at(identity.expires_at) : identity.expires_at
          expires_at < Time.now
        end

        # Refresh the access token for a specific provider
        #
        # @param provider [String, Symbol] The provider name
        # @return [String, nil] The new access token or nil if refresh failed or not supported
        def refresh_oauth_token(provider)
          identity = oauth_identity_for(provider)
          return nil unless identity&.refresh_token.present?

          provider_instance = Clavis.provider(provider)
          return nil unless provider_instance.respond_to?(:refresh_token)

          # Refresh the token
          new_tokens = provider_instance.refresh_token(identity.refresh_token)

          # Update the identity with the new tokens
          identity.token = new_tokens[:token]
          identity.refresh_token = new_tokens[:refresh_token] if new_tokens[:refresh_token].present?
          identity.expires_at = new_tokens[:expires_at] if new_tokens[:expires_at].present?
          identity.save!

          # Return the new token
          identity.token
        end
      end
    end
  end
end
