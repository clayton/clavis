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
            identity.store_standardized_user_info!
            identity.save!

            # Yield to the block if given, to allow customization
            yield(identity.user, auth_hash) if block_given?

            identity.user.save! if identity.user.changed?
            identity.user
          end

          private

          def find_or_create_user_from_oauth(auth_hash)
            # Try to find an existing user by email
            email = auth_hash.dig(:info, :email)

            # Determine the email field name
            email_field = new.respond_to?(:email) ? :email : :email_address

            # Try to find by email
            user = nil
            user = find_by(email_field => email) if email.present?

            # If no user found, create a new one
            if user.nil?
              user = new

              # Set email if present
              user.send("#{email_field}=", email) if email.present? && user.respond_to?("#{email_field}=")

              # Set password if applicable
              if user.respond_to?(:password=)
                password = SecureRandom.hex(16)
                user.password = password
                user.password_confirmation = password if user.respond_to?(:password_confirmation=)
              end

              # Set name if available
              if auth_hash.dig(:info, :name).present?
                name_parts = auth_hash.dig(:info, :name).split
                user.first_name = name_parts.first if user.respond_to?(:first_name=)
                user.last_name = name_parts[1..].join(" ") if name_parts.size > 1 && user.respond_to?(:last_name=)
              end

              # Set other attributes if available
              if user.respond_to?(:avatar_url=) && auth_hash.dig(:info, :image).present?
                user.avatar_url = auth_hash.dig(:info, :image)
              end

              # Save user
              user.save!
            end

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
          rescue Clavis::UnsupportedOperation
            # For unsupported operations, just return the current token
            identity.token
          rescue Clavis::Error
            # For other errors, return nil
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

        # Returns the OAuth avatar URL from the most recent identity
        # or from a specific provider if specified
        def oauth_avatar_url(provider = nil)
          identity = provider ? oauth_identity_for(provider) : latest_oauth_identity
          return nil unless identity

          standardized = identity.auth_data&.dig("standardized") || identity.auth_data&.dig(:standardized)
          standardized&.dig("avatar_url") || standardized&.dig(:avatar_url)
        end

        # Returns the OAuth name from the most recent identity
        # or from a specific provider if specified
        def oauth_name(provider = nil)
          identity = provider ? oauth_identity_for(provider) : latest_oauth_identity
          return nil unless identity

          standardized = identity.auth_data&.dig("standardized") || identity.auth_data&.dig(:standardized)
          standardized&.dig("name") || standardized&.dig(:name)
        end

        # Returns the OAuth email from the most recent identity
        # or from a specific provider if specified
        def oauth_email(provider = nil)
          identity = provider ? oauth_identity_for(provider) : latest_oauth_identity
          return nil unless identity

          standardized = identity.auth_data&.dig("standardized") || identity.auth_data&.dig(:standardized)
          standardized&.dig("email") || standardized&.dig(:email)
        end

        def latest_oauth_identity
          # Handle both ActiveRecord collections and arrays
          if oauth_identities.respond_to?(:order)
            oauth_identities.order(updated_at: :desc).first
          else
            # For non-ActiveRecord, sort manually
            oauth_identities.max_by { |identity| identity.updated_at || Time.at(0) }
          end
        end
      end
    end
  end
end
