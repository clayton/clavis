# frozen_string_literal: true

module Clavis
  module Providers
    class Github < Base
      def initialize(config = {})
        # Support GitHub Enterprise by allowing configuration of base URLs
        site_url = config[:site_url] || "https://api.github.com"
        auth_url = config[:authorize_url] || "https://github.com/login/oauth/authorize"
        token_url = config[:token_url] || "https://github.com/login/oauth/access_token"

        config[:authorization_endpoint] = auth_url
        config[:token_endpoint] = token_url
        config[:userinfo_endpoint] = "#{site_url}/user"
        config[:scope] = config[:scope] || "user:email"

        # Store for later use
        @site_url = site_url

        super
      end

      def authorization_endpoint
        @config[:authorization_endpoint]
      end

      def token_endpoint
        @config[:token_endpoint]
      end

      def userinfo_endpoint
        @config[:userinfo_endpoint]
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
          req.headers["Accept"] = "application/vnd.github.v3+json"
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
        auth_header = response.env.request.headers["Authorization"]
        emails = get_emails(auth_header)

        # Find primary and verified email or fall back to profile email
        primary_email = find_primary_email(emails)
        email = primary_email[:email] if primary_email

        # Fallback to profile email if available
        email ||= data[:email]

        {
          id: data[:id].to_s,
          name: data[:name],
          nickname: data[:login],
          email: email,
          email_verified: primary_email ? primary_email[:verified] : nil,
          image: data[:avatar_url]
        }
      end

      private

      # Find the primary and verified email from the list
      def find_primary_email(emails)
        # First look for primary and verified
        primary = emails.find { |email| email[:primary] && email[:verified] }

        # If no primary+verified found, look for just primary
        primary ||= emails.find { |email| email[:primary] }

        # If no primary found, look for any verified
        primary ||= emails.find { |email| email[:verified] }

        # Return the email or nil
        primary
      end

      def get_emails(auth_header)
        return [] unless auth_header

        # Use the stored site URL to build the emails endpoint
        emails_endpoint = "#{@site_url}/user/emails"

        response = http_client.get(emails_endpoint) do |req|
          req.headers["Authorization"] = auth_header
          req.headers["Accept"] = "application/vnd.github.v3+json"
        end

        if response.status == 200
          JSON.parse(response.body, symbolize_names: true)
        else
          Clavis::Logging.log_custom("github_emails_fetch", false)
          []
        end
      end
    end
  end
end
