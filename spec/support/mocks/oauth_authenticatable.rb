# frozen_string_literal: true

# Mock version of OAuthAuthenticatable for non-Rails tests
module Clavis
  module Models
    module Concerns
      # This is a simplified mock of the OAuthAuthenticatable module
      # for use in non-Rails tests. It doesn't have ActiveRecord dependencies.
      module MockOAuthAuthenticatable
        def oauth_identities
          @oauth_identities ||= []
        end

        def oauth_identity_for(provider)
          oauth_identities.find { |identity| identity.provider.to_s == provider.to_s }
        end

        def connected_to?(provider)
          oauth_identity_for(provider).present?
        end
      end
    end
  end
end
