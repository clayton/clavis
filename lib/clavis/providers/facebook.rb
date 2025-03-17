# frozen_string_literal: true

module Clavis
  module Providers
    class Facebook < Base
      def authorization_endpoint
        "https://www.facebook.com/v18.0/dialog/oauth"
      end

      def token_endpoint
        "https://graph.facebook.com/v18.0/oauth/access_token"
      end

      def userinfo_endpoint
        "https://graph.facebook.com/v18.0/me?fields=id,name,email,picture"
      end

      def default_scopes
        "email public_profile"
      end

      def refresh_token(access_token)
        params = {
          grant_type: "fb_exchange_token",
          client_id: client_id,
          client_secret: client_secret,
          fb_exchange_token: access_token
        }

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
        response = http_client.get(userinfo_endpoint) do |req|
          req.params["access_token"] = access_token
          req.params["fields"] = "id,name,email,first_name,last_name,picture"
        end

        raise Clavis::InvalidAccessToken if response.status != 200

        process_userinfo_response(response)
      end

      protected

      def process_userinfo_response(response)
        data = JSON.parse(response.body, symbolize_names: true)

        # Facebook returns picture as an object, extract URL
        picture_url = data.dig(:picture, :data, :url) if data[:picture]

        {
          id: data[:id],
          name: data[:name],
          email: data[:email],
          given_name: data[:first_name],
          family_name: data[:last_name],
          picture: picture_url
        }
      end
    end
  end
end
