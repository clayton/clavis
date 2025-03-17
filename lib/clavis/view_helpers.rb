# frozen_string_literal: true

module Clavis
  module ViewHelpers
    def oauth_button(provider, options = {})
      # Validate provider configuration
      begin
        Clavis.configuration.validate_provider!(provider)
      rescue Clavis::ProviderNotConfigured
        # Return error message or comment in development/test
        if defined?(Rails) && (Rails.env.development? || Rails.env.test?)
          return content_tag(:div, "#{provider} not configured. Add client_id and client_secret.",
                             class: "clavis-error")
        else
          Clavis::Logging.logger.error("Attempted to use unconfigured provider: #{provider}")
          return nil
        end
      end

      # Render button with proper styling and SVG
      button_text = options.delete(:text) || "Sign in with #{provider.to_s.capitalize}"
      button_class = "clavis-button clavis-#{provider}-button #{options.delete(:class)}"

      link_to auth_authorize_path(provider), class: button_class, method: :post, data: options[:data] do
        provider_svg(provider) + content_tag(:span, button_text)
      end
    end

    def provider_svg(provider)
      case provider.to_sym
      when :google
        <<~SVG.html_safe
          <svg class="clavis-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M12.24 10.285V14.4h6.806c-.275 1.765-2.056 5.174-6.806 5.174-4.095 0-7.439-3.389-7.439-7.574s3.345-7.574 7.439-7.574c2.33 0 3.891.989 4.785 1.849l3.254-3.138C18.189 1.186 15.479 0 12.24 0c-6.635 0-12 5.365-12 12s5.365 12 12 12c6.926 0 11.52-4.869 11.52-11.726 0-.788-.085-1.39-.189-1.989H12.24z"/>
          </svg>
        SVG
      when :github
        <<~SVG.html_safe
          <svg class="clavis-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
          </svg>
        SVG
      when :apple
        <<~SVG.html_safe
          <svg class="clavis-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701"/>
          </svg>
        SVG
      when :facebook
        <<~SVG.html_safe
          <svg class="clavis-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M23.9981 11.9991C23.9981 5.37216 18.626 0 11.9991 0C5.37216 0 0 5.37216 0 11.9991C0 17.9882 4.38789 22.9522 10.1242 23.8524V15.4676H7.07758V11.9991H10.1242V9.35553C10.1242 6.34826 11.9156 4.68714 14.6564 4.68714C15.9692 4.68714 17.3424 4.92149 17.3424 4.92149V7.87439H15.8294C14.3388 7.87439 13.8739 8.79933 13.8739 9.74824V11.9991H17.2018L16.6698 15.4676H13.8739V23.8524C19.6103 22.9522 23.9981 17.9882 23.9981 11.9991Z"/>
          </svg>
        SVG
      when :microsoft
        <<~SVG.html_safe
          <svg class="clavis-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M0 0h11.377v11.372H0zm12.623 0H24v11.372H12.623zM0 12.623h11.377V24H0zm12.623 0H24V24H12.623"/>
          </svg>
        SVG
      else
        content_tag(:div, "", class: "clavis-icon clavis-icon-#{provider}")
      end
    end

    def auth_authorize_path(provider)
      "/auth/#{provider}"
    end

    # Rails helper methods for non-Rails environments
    def content_tag(tag, content_or_options_with_block = nil, options = nil, &block)
      if block_given?
        options = content_or_options_with_block if content_or_options_with_block.is_a?(Hash)
        content = capture(&block)
      else
        content = content_or_options_with_block
      end

      options ||= {}
      tag_options = tag_options(options)

      "<#{tag}#{tag_options}>#{content}</#{tag}>"
    end

    def link_to(name = nil, options = nil, html_options = nil, &block)
      if block_given?
        html_options = options
        options = name
        name = capture(&block)
      end
      options ||= {}
      html_options ||= {}

      url = url_for(options)
      html_options = convert_options_to_data_attributes(options, html_options)
      tag_options = tag_options(html_options)

      href = "href=\"#{url}\"" unless url.nil?
      "<a #{href}#{tag_options}>#{name}</a>"
    end

    def url_for(options)
      case options
      when String
        options
      when Hash
        options[:controller] ||= controller_name
        options[:action] ||= action_name

        path = "/#{options[:controller]}/#{options[:action]}"
        path += "/#{options[:id]}" if options[:id]
        path
      else
        options.to_s
      end
    end

    def tag_options(options)
      return "" if options.empty?

      attrs = []
      options.each_pair do |key, value|
        if key.to_s == "data" && value.is_a?(Hash)
          value.each_pair do |k, v|
            attrs << data_tag_option("data-#{k}", v)
          end
        elsif key.to_s == "class" && value.is_a?(Array)
          attrs << tag_option(key, value.join(" "))
        else
          attrs << tag_option(key, value)
        end
      end

      " #{attrs.join(" ")}" unless attrs.empty?
    end

    def tag_option(key, value)
      "#{key}=\"#{value}\""
    end

    def data_tag_option(key, value)
      "#{key}=\"#{value}\""
    end

    def convert_options_to_data_attributes(_options, html_options)
      html_options["data-method"] = html_options.delete(:method) if html_options.key?(:method)

      html_options
    end

    def capture(&block)
      block.call
    end

    def controller_name
      "auth"
    end

    def action_name
      "index"
    end
  end
end
