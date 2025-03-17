# frozen_string_literal: true

require "securerandom"

module Clavis
  module Utils
    module SecureToken
      def self.generate_state
        SecureRandom.hex(24)
      end

      def self.generate_nonce
        SecureRandom.hex(16)
      end
    end
  end
end
