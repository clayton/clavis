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
        "https://graph.facebook.com/v18.0/me"
      end

      def default_scopes
        "email public_profile"
      end

      def get_user_info(access_token)
        # Facebook requires fields parameter to specify what data to return
        response = http_client.get(userinfo_endpoint) do |req|
          req.params["access_token"] = access_token
          req.params["fields"] = "id,name,email,first_name,last_name,picture"
        end

        raise Clavis::InvalidAccessToken.new if response.status != 200

        process_userinfo_response(response)
      end

      protected

      def process_userinfo_response(response)
        data = JSON.parse(response.body, symbolize_names: true)

        {
          id: data[:id],
          name: data[:name],
          email: data[:email],
          given_name: data[:first_name],
          family_name: data[:last_name],
          picture: data.dig(:picture, :data, :url)
        }
      end
    end
  end
end
