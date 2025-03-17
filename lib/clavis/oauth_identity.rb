# frozen_string_literal: true

module Clavis
  class OauthIdentity < ActiveRecord::Base
    belongs_to :user, polymorphic: true

    validates :provider, presence: true
    validates :uid, presence: true
    validates :user, presence: true
    validates :uid, uniqueness: { scope: :provider }

    serialize :auth_data, JSON

    def token_expired?
      expires_at.present? && expires_at < Time.current
    end

    def token_valid?
      token.present? && !token_expired?
    end

    def ensure_fresh_token
      return token unless token_expired?
      return nil unless refresh_token.present?

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
  end
end
