# frozen_string_literal: true

module Clavis
  module Providers
    class Github < Base
      def initialize(config = {})
        config[:authorization_endpoint] = "https://github.com/login/oauth/authorize"
        config[:token_endpoint] = "https://github.com/login/oauth/access_token"
        config[:userinfo_endpoint] = "https://api.github.com/user"
        config[:scope] = config[:scope] || "user:email"
        super
      end

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

      def get_user_info(access_token)
        return {} unless userinfo_endpoint

        # Validate inputs
        raise Clavis::InvalidToken unless Clavis::Security::InputValidator.valid_token?(access_token)

        response = http_client.get(userinfo_endpoint) do |req|
          req.headers["Authorization"] = "Bearer #{access_token}"
        end

        if response.status != 200
          Clavis::Logging.log_userinfo_request(provider_name, false)
          handle_userinfo_error_response(response)
        end

        Clavis::Logging.log_userinfo_request(provider_name, true)

        process_userinfo_response(response)
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
