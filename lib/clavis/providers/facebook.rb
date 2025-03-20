# frozen_string_literal: true

module Clavis
  module Providers
    class Facebook < Base
      # Updated to use the latest stable Facebook API version
      FACEBOOK_API_VERSION = "v19.0"

      def initialize(config = {})
        config[:authorization_endpoint] = "https://www.facebook.com/#{FACEBOOK_API_VERSION}/dialog/oauth"
        config[:token_endpoint] = "https://graph.facebook.com/#{FACEBOOK_API_VERSION}/oauth/access_token"
        config[:userinfo_endpoint] = "https://graph.facebook.com/#{FACEBOOK_API_VERSION}/me"
        config[:scope] = config[:scope] || "email public_profile"
        # Store additional Facebook-specific options
        @image_size = config[:image_size] || {}
        @display = config[:display]
        @auth_type = config[:auth_type]
        @secure_image_url = config.fetch(:secure_image_url, true)
        super
      end

      def authorization_endpoint
        "https://www.facebook.com/#{FACEBOOK_API_VERSION}/dialog/oauth"
      end

      def token_endpoint
        "https://graph.facebook.com/#{FACEBOOK_API_VERSION}/oauth/access_token"
      end

      def userinfo_endpoint
        "https://graph.facebook.com/#{FACEBOOK_API_VERSION}/me"
      end

      def default_scopes
        "email public_profile"
      end

      # Override authorize_url to add Facebook-specific parameters
      def authorize_url(state:, nonce:, scope: nil)
        url = super

        # Add Facebook-specific parameters if present
        params = {}
        params[:display] = @display if @display
        params[:auth_type] = @auth_type if @auth_type

        # Append additional parameters if any were added
        if params.any?
          uri = URI.parse(url)
          existing_params = URI.decode_www_form(uri.query || "").to_h
          all_params = existing_params.merge(params)
          uri.query = URI.encode_www_form(all_params)
          uri.to_s
        else
          url
        end
      end

      def refresh_token(access_token)
        params = {
          grant_type: "fb_exchange_token",
          client_id: client_id,
          client_secret: client_secret,
          fb_exchange_token: access_token
        }

        # Add appsecret_proof for enhanced security
        params[:appsecret_proof] = generate_appsecret_proof(access_token)

        response = http_client.get("#{token_endpoint}?#{to_query(params)}")

        if response.status != 200
          Clavis::Logging.log_token_refresh(provider_name, false)
          handle_token_error_response(response)
        end

        Clavis::Logging.log_token_refresh(provider_name, true)
        parse_token_response(response)
      end

      def get_user_info(access_token)
        # Facebook requires fields parameter to specify what data to return
        # Enhanced with more fields for richer user profiles
        fields = "id,name,email,first_name,last_name,picture,link,verified,location,age_range,birthday,gender"

        response = http_client.get(userinfo_endpoint) do |req|
          req.params["access_token"] = access_token
          req.params["fields"] = fields
          req.params["appsecret_proof"] = generate_appsecret_proof(access_token)
        end

        if response.status != 200
          Clavis::Logging.log_userinfo_request(provider_name, false)
          handle_userinfo_error_response(response)
        end

        Clavis::Logging.log_userinfo_request(provider_name, true)
        process_userinfo_response(response)
      end

      # Exchanges short-lived token for a long-lived token
      def exchange_for_long_lived_token(access_token)
        params = {
          grant_type: "fb_exchange_token",
          client_id: client_id,
          client_secret: client_secret,
          fb_exchange_token: access_token
        }

        response = http_client.get("#{token_endpoint}?#{to_query(params)}")

        if response.status != 200
          Clavis::Logging.log_custom("facebook_long_lived_token_exchange", false)
          handle_token_error_response(response)
        end

        Clavis::Logging.log_custom("facebook_long_lived_token_exchange", true)
        parse_token_response(response)
      end

      protected

      def process_userinfo_response(response)
        data = JSON.parse(response.body, symbolize_names: true)

        # Facebook returns picture as an object, extract URL with proper handling
        picture_url = nil
        if data[:picture]
          if data[:picture].is_a?(Hash) && data[:picture][:data]
            picture_url = data[:picture][:data][:url]
          elsif data[:picture].is_a?(String)
            picture_url = data[:picture]
          end
        end

        # Enhanced data structure with more fields
        result = {
          id: data[:id],
          name: data[:name],
          email: data[:email],
          given_name: data[:first_name],
          family_name: data[:last_name],
          picture: picture_url
        }

        # Add optional fields when present
        result[:verified] = data[:verified] if data.key?(:verified)
        result[:link] = data[:link] if data.key?(:link)
        result[:location] = data[:location][:name] if data[:location].is_a?(Hash) && data[:location][:name]
        result[:gender] = data[:gender] if data.key?(:gender)
        result[:birthday] = data[:birthday] if data.key?(:birthday)
        result[:age_range] = data[:age_range] if data.key?(:age_range)

        result
      end

      private

      # Generate appsecret_proof for enhanced security
      # This is a SHA-256 HMAC of the access token, using the app secret as the key
      def generate_appsecret_proof(access_token)
        return nil unless client_secret && access_token

        require "openssl"
        OpenSSL::HMAC.hexdigest(
          OpenSSL::Digest.new("sha256"),
          client_secret,
          access_token
        )
      end

      # Helper method to build image URLs with size options
      def image_url(uid)
        return nil unless uid

        uri_class = @secure_image_url ? URI::HTTPS : URI::HTTP
        site_uri = URI.parse("https://graph.facebook.com/#{FACEBOOK_API_VERSION}")

        url = uri_class.build({
                                host: site_uri.host,
                                path: "#{site_uri.path}/#{uid}/picture"
                              })

        query = {}

        if @image_size.is_a?(String) || @image_size.is_a?(Symbol)
          query[:type] = @image_size
        elsif @image_size.is_a?(Hash)
          query.merge!(@image_size)
        end

        url.query = Rack::Utils.build_query(query) unless query.empty?
        url.to_s
      end
    end
  end
end
