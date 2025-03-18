# frozen_string_literal: true

module Clavis
  module Security
    # Mock TokenStorage for testing
    module TokenStorage
      def self.encrypt(value)
        value
      end

      def self.decrypt(value)
        value
      end
    end
  end
end
