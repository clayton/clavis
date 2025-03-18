# frozen_string_literal: true

module Clavis
  # Normalizes user information from different OAuth providers into a standard format
  class UserInfoNormalizer
    # Takes raw provider user_info and extracts standard fields
    def self.normalize(provider_name, user_info)
      return {} unless user_info.is_a?(Hash)

      {
        email: extract_email(provider_name, user_info),
        name: extract_name(provider_name, user_info),
        avatar_url: extract_avatar(provider_name, user_info)
      }
    end

    def self.extract_email(provider, user_info)
      # Handle both string and symbol keys
      email = user_info[:email] || user_info["email"]

      # Provider-specific handling
      case provider.to_sym
      when :apple
        email || user_info[:email_verified] || user_info["email_verified"]
      else
        # Default behavior for all other providers (google, github, facebook, microsoft)
        email
      end
    end

    def self.extract_name(provider, user_info)
      # Handle both string and symbol keys
      name = user_info[:name] || user_info["name"]
      first_name = user_info[:first_name] || user_info["first_name"]
      last_name = user_info[:last_name] || user_info["last_name"]

      # Provider-specific handling
      case provider.to_sym
      when :google, :github, :facebook, :microsoft
        name
      when :apple
        if name && !name.empty?
          name
        elsif (first_name && !first_name.empty?) || (last_name && !last_name.empty?)
          [first_name, last_name].compact.join(" ")
        end
      else
        name || [first_name, last_name].compact.join(" ")
      end
    end

    def self.extract_avatar(provider, user_info)
      # Handle various avatar field names across providers
      case provider.to_sym
      when :google, :facebook
        user_info[:picture] || user_info["picture"]
      when :github
        user_info[:avatar_url] || user_info["avatar_url"]
      when :microsoft
        user_info[:avatar] || user_info["avatar"]
      else
        # Try common field names
        user_info[:picture] ||
          user_info["picture"] ||
          user_info[:avatar_url] ||
          user_info["avatar_url"] ||
          user_info[:avatar] ||
          user_info["avatar"] ||
          user_info[:image] ||
          user_info["image"]
      end
    end
  end
end
