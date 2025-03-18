# frozen_string_literal: true

module Clavis
  if defined?(ActiveRecord::Base)
    class OauthIdentity < ActiveRecord::Base
      belongs_to :authenticatable, polymorphic: true

      validates :provider, presence: true
      validates :uid, presence: true
      validates :authenticatable, presence: true
      validates :uid, uniqueness: { scope: :provider }

      # Use serialize with a single argument if Rails 7.1+ is detected
      if defined?(Rails::VERSION) &&
         Gem::Version.new(Rails::VERSION::STRING) >= Gem::Version.new("7.1")
        serialize :auth_data
      else
        serialize :auth_data, JSON
      end

      # Override token getter to decrypt the token
      def token
        Clavis::Security::TokenStorage.decrypt(self[:token])
      end

      # Override token setter to encrypt the token
      def token=(value)
        encrypted_token = Clavis::Security::TokenStorage.encrypt(value)
        self[:token] = encrypted_token
      end

      # Override refresh_token getter to decrypt the token
      def refresh_token
        Clavis::Security::TokenStorage.decrypt(self[:refresh_token])
      end

      # Override refresh_token setter to encrypt the token
      def refresh_token=(value)
        encrypted_token = Clavis::Security::TokenStorage.encrypt(value)
        self[:refresh_token] = encrypted_token
      end

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
          Clavis::Logging.log_token_refresh(provider, false, e.message)
          token
        rescue Clavis::Error => e
          Clavis::Logging.log_error(e)
          nil
        end
      end

      # Store standardized user info in the auth_data field
      def store_standardized_user_info!
        return unless auth_data.present?

        normalized = Clavis::UserInfoNormalizer.normalize(provider, auth_data)

        # Store the normalized data in auth_data under a standardized key
        self.auth_data = auth_data.merge("standardized" => normalized)
        save! if persisted?
      end
    end
  else
    # Stub class for environments where ActiveRecord is not available
    class OauthIdentity
      attr_accessor :provider, :uid, :token, :refresh_token, :expires_at, :authenticatable, :updated_at

      # Custom accessor for auth_data to ensure it's always initialized as a hash
      def auth_data
        @auth_data ||= {}
      end

      def auth_data=(value)
        @auth_data = value || {}
      end

      def initialize(attributes = {})
        @provider = attributes[:provider]
        @uid = attributes[:uid]
        @token = attributes[:token]
        @refresh_token = attributes[:refresh_token]
        @expires_at = attributes[:expires_at]
        self.auth_data = attributes[:auth_data]
        @authenticatable = attributes[:authenticatable]
        @persisted = attributes[:persisted] || false
        @updated_at = attributes[:updated_at] || Time.now
      end

      def token_expired?
        !expires_at.nil? && expires_at < Time.now
      end

      def token_valid?
        !token.nil? && !token.empty? && !token_expired?
      end

      def persisted?
        @persisted
      end

      def save!
        @persisted = true
        self
      end

      def ensure_fresh_token
        return token unless token_expired?
        return nil unless refresh_token && !refresh_token.empty?

        begin
          provider_instance = Clavis.provider(
            provider.to_sym,
            redirect_uri: Clavis.configuration.providers.dig(provider.to_sym, :redirect_uri)
          )

          new_tokens = provider_instance.refresh_token(refresh_token)

          self.token = new_tokens[:access_token]
          self.refresh_token = new_tokens[:refresh_token] || refresh_token
          self.expires_at = new_tokens[:expires_at] ? Time.at(new_tokens[:expires_at]) : nil

          token
        rescue Clavis::UnsupportedOperation => e
          Clavis::Logging.log_token_refresh(provider, false, e.message)
          token
        rescue Clavis::Error => e
          Clavis::Logging.log_error(e)
          nil
        end
      end

      # Store standardized user info in the auth_data field
      def store_standardized_user_info!
        return unless auth_data.present?

        normalized = Clavis::UserInfoNormalizer.normalize(provider, auth_data)

        # Store the normalized data in auth_data under a standardized key
        self.auth_data = auth_data.merge("standardized" => normalized)
        save! if persisted?
      end
    end
  end
end
