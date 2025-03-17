# frozen_string_literal: true

module Clavis
  module Providers
    class Base
      attr_reader :client_id, :client_secret, :redirect_uri

      def initialize(options = {})
        @client_id = options[:client_id]
        @client_secret = options[:client_secret]
        @redirect_uri = options[:redirect_uri]
      end

      def authorize_url(options = {})
        "https://example.com/auth?client_id=#{client_id}&redirect_uri=#{redirect_uri}&state=#{options[:state]}"
      end

      def process_callback(_code, _state = nil)
        {
          provider: "base",
          uid: "123",
          info: {
            email: "user@example.com"
          },
          credentials: {
            token: "mock_token",
            refresh_token: "mock_refresh_token",
            expires_at: Time.now.to_i + 3600
          }
        }
      end

      def refresh_token(_refresh_token)
        {
          access_token: "new_mock_token",
          refresh_token: "new_mock_refresh_token",
          expires_at: Time.now.to_i + 3600
        }
      end
    end

    class Google < Base
      def initialize(options = {})
        super
      end
    end

    class Github < Base
      def initialize(options = {})
        super
      end
    end

    class Facebook < Base
      def initialize(options = {})
        super
      end
    end

    class Apple < Base
      def initialize(options = {})
        super
      end
    end

    class Microsoft < Base
      def initialize(options = {})
        super
      end
    end

    class Generic < Base
      def initialize(options = {})
        super
      end
    end
  end
end
