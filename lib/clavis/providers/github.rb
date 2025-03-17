# frozen_string_literal: true

module Clavis
  module Providers
    class GitHub < Base
      def authorization_endpoint
        "https://github.com/login/oauth/authorize"
      end

      def token_endpoint
        "https://github.com/login/oauth/access_token"
      end

      def userinfo_endpoint
        "https://api.github.com/user"
      end

      def default_scopes
        "user:email"
      end

      protected

      def process_userinfo_response(response)
        data = JSON.parse(response.body, symbolize_names: true)

        # GitHub doesn't include email in the user response if it's private
        # We need to make a separate request to get the emails
        emails = get_emails(response.env.request.headers["Authorization"])
        primary_email = emails.find { |email| email[:primary] }

        {
          id: data[:id].to_s,
          name: data[:name],
          nickname: data[:login],
          email: primary_email ? primary_email[:email] : data[:email],
          email_verified: primary_email ? primary_email[:verified] : nil,
          image: data[:avatar_url]
        }
      end

      private

      def get_emails(auth_header)
        return [] unless auth_header

        response = http_client.get("https://api.github.com/user/emails") do |req|
          req.headers["Authorization"] = auth_header
        end

        if response.status == 200
          JSON.parse(response.body, symbolize_names: true)
        else
          []
        end
      end
    end
  end
end
