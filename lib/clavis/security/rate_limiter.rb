# frozen_string_literal: true

module Clavis
  module Security
    # RateLimiter provides integration with Rack::Attack for protecting Clavis endpoints
    # against DDoS and brute force attacks.
    module RateLimiter
      class << self
        # Configures Rack::Attack with default throttling rules for Clavis
        # @param app [Rails::Application] The Rails application
        def configure(_app)
          return unless defined?(Rack::Attack)

          # Skip if rate limiting is disabled
          return unless Clavis.configuration.rate_limiting_enabled

          Clavis.logger.info("Configuring Rack::Attack for Clavis endpoints")

          configure_throttles
          configure_blocklist
          configure_response
        end

        # Configures throttling rules for Clavis endpoints
        def configure_throttles
          return unless defined?(Rack::Attack)

          # Throttle login attempts for a given email parameter
          Rack::Attack.throttle("clavis/auth/callback/email", limit: 5, period: 20.seconds) do |req|
            if req.path =~ %r{/auth/\w+/callback} && req.params["email"].present?
              # Throttle by normalized email
              req.params["email"].to_s.downcase.gsub(/\s+/, "")
            end
          end

          # Throttle OAuth callback attempts by IP address
          Rack::Attack.throttle("clavis/auth/callback/ip", limit: 15, period: 60.seconds) do |req|
            req.ip if req.path =~ %r{/auth/\w+/callback}
          end

          # Throttle OAuth authorize endpoints
          Rack::Attack.throttle("clavis/auth/authorize/ip", limit: 20, period: 60.seconds) do |req|
            req.ip if req.path =~ %r{/auth/\w+} && !req.path.include?("/callback")
          end

          # Allow custom throttles to be defined via configuration
          Clavis.configuration.custom_throttles.each do |name, config|
            Rack::Attack.throttle("clavis/#{name}", limit: config[:limit], period: config[:period].seconds) do |req|
              instance_exec(req, &config[:block]) if config[:block].respond_to?(:call)
            end
          end
        end

        # Configures blocklist rules
        def configure_blocklist
          return unless defined?(Rack::Attack)

          # Block failed login attempts
          Rack::Attack.blocklist("clavis/fail2ban") do |req|
            Rack::Attack::Fail2Ban.filter("clavis-pentesters-#{req.ip}", maxretry: 5, findtime: 10.minutes,
                                                                         bantime: 30.minutes) do
              req.path =~ %r{/auth/\w+/callback} && req.env["rack.attack.match_data"]
            end
          end
        end

        # Configures Rack::Attack response
        def configure_response
          return unless defined?(Rack::Attack)

          Rack::Attack.throttled_responder = lambda do |_req|
            [
              429, # status
              { "Content-Type" => "application/json" }, # headers
              [{ error: "Rate limit exceeded. Please retry later." }.to_json] # body
            ]
          end
        end

        # Installs Rack::Attack in the Rails application
        # @param app [Rails::Application] The Rails application
        def install(app)
          return unless defined?(Rack::Attack)

          # Skip if rate limiting is disabled
          return unless Clavis.configuration.rate_limiting_enabled

          # Add Rack::Attack as middleware if not already included
          # Check if Rack::Attack is already in the middleware stack
          rack_attack_included = false

          if app.middleware.respond_to?(:each)
            app.middleware.each do |middleware|
              if middleware.klass == Rack::Attack
                rack_attack_included = true
                break
              end
            end
          end

          # Add Rack::Attack if not already included
          app.middleware.use(Rack::Attack) unless rack_attack_included

          configure(app)
        end
      end
    end
  end
end
