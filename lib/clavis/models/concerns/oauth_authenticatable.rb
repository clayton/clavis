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
                   as: :authenticatable,
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
        # @return [Boolean] True if the user has any OAuth identities or oauth_user flag is true
        def oauth_user?
          return true if respond_to?(:oauth_user) && oauth_user

          # Handle both Array and ActiveRecord collection
          if oauth_identities.respond_to?(:exists?)
            oauth_identities.exists?
          else
            oauth_identities.any?
          end
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
          return nil unless oauth_identity&.auth_data

          # First check standardized data
          email = extract_standardized_value(oauth_identity.auth_data, "email")

          # Fall back to raw auth data
          email ||= oauth_identity.auth_data["email"] || oauth_identity.auth_data[:email]
          email
        end

        # Get the name from the OAuth identity
        #
        # @return [String, nil] The name from the OAuth identity or nil
        def oauth_name
          return nil unless oauth_identity&.auth_data

          # First check standardized data
          name = extract_standardized_value(oauth_identity.auth_data, "name")

          # Fall back to raw auth data
          name ||= oauth_identity.auth_data["name"] || oauth_identity.auth_data[:name]
          name
        end

        # Get the profile picture URL from the OAuth identity
        #
        # @return [String, nil] The profile picture URL from the OAuth identity or nil
        def oauth_avatar_url
          return nil unless oauth_identity&.auth_data

          # First check standardized data
          avatar = extract_standardized_value(oauth_identity.auth_data, "avatar_url")

          # Fall back to various possible fields in raw auth data
          avatar ||= oauth_identity.auth_data["image"] || oauth_identity.auth_data[:image]
          avatar ||= oauth_identity.auth_data["picture"] || oauth_identity.auth_data[:picture]
          avatar ||= oauth_identity.auth_data["avatar_url"] || oauth_identity.auth_data[:avatar_url]

          avatar
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
          oauth_identity.token = new_tokens[:access_token] || new_tokens[:token]
          oauth_identity.refresh_token = new_tokens[:refresh_token] if new_tokens[:refresh_token].present?
          oauth_identity.expires_at = new_tokens[:expires_at] if new_tokens[:expires_at].present?
          oauth_identity.save!

          # Return the new token
          oauth_identity.token
        end

        private

        # Extract a value from standardized data, supporting both string and symbol keys
        def extract_standardized_value(auth_data, key)
          # Try string keys first
          if auth_data.key?("standardized") && auth_data["standardized"].is_a?(Hash)
            value = auth_data["standardized"][key]
            return value if value
          end

          # Then try symbol keys
          if auth_data.key?(:standardized) && auth_data[:standardized].is_a?(Hash)
            value = auth_data[:standardized][key.to_sym]
            return value if value
          end

          # No standardized value found
          nil
        end
      end
    end
  end
end
