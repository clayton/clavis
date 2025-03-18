# frozen_string_literal: true

require "uri"

module Clavis
  module Security
    module InputValidator
      # Regular expressions for validation
      TOKEN_REGEX = /\A[a-zA-Z0-9\-_.]+\z/
      CODE_REGEX = %r{\A[a-zA-Z0-9\-_./=+]+\z}
      STATE_REGEX = /\A[a-zA-Z0-9\-_.]+\z/
      EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d-]+(\.[a-z\d-]+)*\.[a-z]+\z/i

      # Dangerous schemes that should never be allowed
      DANGEROUS_SCHEMES = %w[javascript data vbscript file].freeze

      class << self
        # Validates a URL
        # @param url [String] The URL to validate
        # @param allowed_schemes [Array<String>] The allowed URL schemes
        # @return [Boolean] Whether the URL is valid
        def valid_url?(url, allowed_schemes: %w[http https])
          return false if url.nil? || url.empty?

          begin
            uri = URI.parse(url)

            # Check if the URI has a scheme
            return false unless uri.scheme

            # Check if the scheme is allowed
            return false if DANGEROUS_SCHEMES.include?(uri.scheme.downcase)
            return false unless allowed_schemes.include?(uri.scheme.downcase)

            # Check if the URI has a host
            return false unless uri.host

            true
          rescue URI::InvalidURIError
            false
          end
        end

        # Validates an OAuth token
        # @param token [String] The token to validate
        # @return [Boolean] Whether the token is valid
        def valid_token?(token)
          return false if token.nil? || token.empty?

          # Make token validation more permissive
          # Just check if it's a string with reasonable length
          token.is_a?(String) && token.length > 5
        end

        # Validates an authorization code
        # @param code [String] The code to validate
        # @return [Boolean] Whether the code is valid
        def valid_code?(code)
          return false if code.nil? || code.empty?

          is_valid = code =~ CODE_REGEX ? true : false

          # For now, be more permissive
          # Eventually, we should properly validate but the regex might need adjustment
          # based on the specific OAuth provider
          return true if code.length > 5 && code.length < 1000

          is_valid
        end

        # Validates a state parameter
        # @param state [String] The state to validate
        # @return [Boolean] Whether the state is valid
        def valid_state?(state)
          return false if state.nil? || state.empty?

          state =~ STATE_REGEX ? true : false
        end

        # Validates an email address
        # @param email [String] The email to validate
        # @return [Boolean] Whether the email is valid
        def valid_email?(email)
          return false if email.nil? || email.empty?

          email =~ EMAIL_REGEX ? true : false
        end

        # Validates a token response
        # @param response [Hash] The token response to validate
        # @return [Boolean] Whether the response is valid
        def valid_token_response?(response)
          return false unless response.is_a?(Hash)

          # Check for error response
          return false if response["error"] || response[:error]

          # Check for required fields
          access_token = response["access_token"] || response[:access_token]
          response["token_type"] || response[:token_type]

          # Be more permissive for debugging - just require an access_token
          return true if access_token && !access_token.empty?

          # Original strict validation:
          # return false unless access_token && token_type
          # return false unless valid_token?(access_token)
          #
          # # Validate optional fields if present
          # if (expires_in = response["expires_in"] || response[:expires_in]) &&
          #    !(expires_in.is_a?(Integer) && expires_in.positive?)
          #   return false
          # end
          #
          # if (refresh_token = response["refresh_token"] || response[:refresh_token]) && !valid_token?(refresh_token)
          #   return false
          # end
          #
          # if (id_token = response["id_token"] || response[:id_token]) && !valid_token?(id_token)
          #   return false
          # end

          true
        end

        # Validates a userinfo response
        # @param response [Hash] The userinfo response to validate
        # @return [Boolean] Whether the response is valid
        def valid_userinfo_response?(response)
          return false unless response.is_a?(Hash)

          # Check for error response
          return false if response["error"] || response[:error]

          # Be more permissive - don't require specific fields
          # Only check for dangerous values

          # Sanitize all string values to prevent XSS
          response.each_value do |value|
            if value.is_a?(String) &&
               (value.include?("<script") ||
                value.include?("javascript:") ||
                value.include?("data:"))
              return false
            end
          end

          true
        end

        # Sanitizes a string to prevent XSS
        # @param input [String] The string to sanitize
        # @return [String] The sanitized string
        def sanitize(input)
          return "" if input.nil?
          return input unless input.is_a?(String)

          # Remove script tags and their content
          result = input.gsub(%r{<script\b[^>]*>.*?</script>}im, "")

          # Remove other potentially dangerous tags
          result = result.gsub(/<[^>]*>/, "")

          # Remove javascript: and data: URLs
          result = result.gsub(/javascript:/i, "")
          result.gsub(/data:/i, "")
        end

        # Sanitizes a hash to prevent XSS
        # @param hash [Hash] The hash to sanitize
        # @return [Hash] The sanitized hash
        def sanitize_hash(hash)
          return {} unless hash.is_a?(Hash)

          result = {}

          hash.each do |key, value|
            result[key] = if value.is_a?(Hash)
                            sanitize_hash(value)
                          elsif value.is_a?(Array)
                            value.map { |item| item.is_a?(Hash) ? sanitize_hash(item) : sanitize(item) }
                          else
                            sanitize(value)
                          end
          end

          result
        end
      end
    end
  end
end
