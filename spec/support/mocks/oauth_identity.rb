# frozen_string_literal: true

module Clavis
  # This is a mock version of OauthIdentity for testing purposes
  unless defined?(ActiveRecord)
    class OauthIdentity
      attr_accessor :provider, :uid, :token, :refresh_token, :expires_at, :auth_data

      def initialize(attributes = {})
        @provider = attributes[:provider]
        @uid = attributes[:uid]
        @token = attributes[:token]
        @refresh_token = attributes[:refresh_token]
        @expires_at = attributes[:expires_at]
        @auth_data = attributes[:auth_data]
      end

      def token_expired?
        # Use present? helper to avoid ActiveSupport dependency
        present?(expires_at) && expires_at < Time.now
      end

      def token_valid?
        present?(token) && !token_expired?
      end

      def ensure_fresh_token
        return token unless token_expired?
        return nil unless present?(refresh_token)

        begin
          provider_instance = Clavis.provider(
            provider.to_sym,
            redirect_uri: Clavis.configuration.providers.dig(provider.to_sym, :redirect_uri)
          )

          new_tokens = provider_instance.refresh_token(refresh_token)

          update(
            token: new_tokens[:access_token],
            refresh_token: new_tokens[:refresh_token] || refresh_token,
            expires_at: new_tokens[:expires_at] ? Time.at(new_tokens[:expires_at]) : nil
          )

          token
        rescue Clavis::UnsupportedOperation => e
          Rails.logger.info("Token refresh not supported for #{provider}: #{e.message}")
          token
        rescue Clavis::Error => e
          Rails.logger.error("Failed to refresh token for #{provider}: #{e.message}")
          nil
        end
      end

      def update(attributes = {})
        attributes.each do |key, value|
          send("#{key}=", value)
        end
        true
      end

      private

      # Helper method to check for nil or empty
      def blank?(obj)
        obj.nil? || obj == ""
      end

      # Helper method for present?
      def present?(obj)
        !blank?(obj)
      end
    end
  end
end
