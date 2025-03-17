# frozen_string_literal: true

# This file is kept for backward compatibility
# The functionality has been moved to Clavis::Security::CsrfProtection

module Clavis
  module Utils
    module StateStore
      def self.generate_state
        Clavis::Security::CsrfProtection.generate_state
      end

      def self.validate_state!(actual_state, expected_state)
        Clavis::Security::CsrfProtection.validate_state!(actual_state, expected_state)
      end
    end
  end
end
