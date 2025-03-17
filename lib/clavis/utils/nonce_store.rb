# frozen_string_literal: true

# This file is kept for backward compatibility
# The functionality has been moved to Clavis::Security::CsrfProtection

module Clavis
  module Utils
    module NonceStore
      def self.generate_nonce
        Clavis::Security::CsrfProtection.generate_nonce
      end
    end
  end
end
