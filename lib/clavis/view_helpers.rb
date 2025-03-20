# frozen_string_literal: true

module Clavis
  module ViewHelpers
    # Generates an OAuth button for the specified provider
    #
    # @param provider [Symbol] The provider to generate a button for
    # @param options [Hash] Options for the button
    # @option options [String] :text Custom text for the button
    # @option options [String] :class Custom CSS class for the button
    # @option options [String] :icon Custom icon for the button
    # @option options [String] :icon_class Custom CSS class for the icon
    # @option options [String] :method HTTP method for the button (default: :get)
    # @option options [Hash] :html HTML attributes for the button
    # @return [String] HTML for the button
    def clavis_oauth_button(provider, options = {})
      provider = provider.to_sym

      # Default options
      options = {
        text: clavis_default_button_text(provider),
        class: clavis_default_button_class(provider),
        icon: clavis_default_button_icon(provider),
        icon_class: clavis_default_icon_class(provider),
        method: :get,
        html: {}
      }.merge(options)

      # More aggressive Turbo disabling - ensure it works in all environments
      options[:html] ||= {}
      options[:html]["data-turbo"] = "false"
      options[:html]["data-turbo-frame"] = "_top"
      options[:html]["rel"] = "nofollow"

      # Generate the button with a direct path to the auth endpoint
      clavis_link_to(
        clavis_oauth_button_content(provider, options),
        clavis_auth_authorize_path(provider),
        method: options[:method],
        class: options[:class],
        **options[:html]
      ).html_safe
    end

    private

    def clavis_oauth_button_content(_provider, options)
      content = ""

      # Add icon if available
      if options[:icon].present?
        icon_html = clavis_provider_svg(options[:icon])
        content += clavis_content_tag(:span, icon_html.html_safe, class: options[:icon_class])
      end

      # Add text
      content += clavis_content_tag(:span, options[:text], class: "clavis-oauth-button__text")

      content
    end

    def clavis_auth_path(provider)
      if defined?(clavis) && clavis.respond_to?("auth_#{provider}_path")
        # Use the engine routing proxy if available
        clavis.send("auth_#{provider}_path")
      elsif defined?(clavis) && clavis.respond_to?(:auth_path)
        # Fallback to generic auth path with provider param
        clavis.auth_path(provider: provider)
      else
        # Last resort: construct the path manually
        # This path is relative to the engine mount point
        "/#{provider}"
      end
    end

    def clavis_default_button_text(provider)
      case provider
      when :google
        "Sign in with Google"
      when :github
        "Sign in with GitHub"
      when :facebook
        "Sign in with Facebook"
      when :apple
        "Sign in with Apple"
      when :microsoft
        "Sign in with Microsoft"
      else
        "Sign in with #{provider.to_s.titleize}"
      end
    end

    def clavis_default_button_class(provider)
      "clavis-oauth-button clavis-oauth-button--#{provider}"
    end

    def clavis_default_button_icon(provider)
      case provider
      when :google
        "google"
      when :github
        "github"
      when :facebook
        "facebook"
      when :apple
        "apple"
      when :microsoft
        "microsoft"
      else
        "oauth"
      end
    end

    def clavis_default_icon_class(provider)
      "clavis-oauth-button__icon clavis-oauth-button__icon--#{provider}"
    end

    def clavis_provider_svg(provider)
      case provider.to_sym
      when :google
        <<~SVG.html_safe
          <svg class="clavis-icon" width="18" height="18" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">
            <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
            <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
            <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
            <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
            <path fill="none" d="M0 0h48v48H0z"/>
          </svg>
        SVG
      when :github
        <<~SVG.html_safe
          <svg class="clavis-icon" width="18" height="18" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">
            <path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.82-1.22-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
          </svg>
        SVG
      when :apple
        <<~SVG.html_safe
          <svg class="clavis-icon" width="16" height="16" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512">
            <path fill="currentColor" d="M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z"/>
          </svg>
        SVG
      when :facebook
        <<~SVG.html_safe
          <svg class="clavis-icon" width="18" height="18" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 512">
            <path fill="currentColor" d="M279.14 288l14.22-92.66h-88.91v-60.13c0-25.35 12.42-50.06 52.24-50.06h40.42V6.26S260.43 0 225.36 0c-73.22 0-121.08 44.38-121.08 124.72v70.62H22.89V288h81.39v224h100.17V288z"/>
          </svg>
        SVG
      when :microsoft
        <<~SVG.html_safe
          <svg class="clavis-icon" width="18" height="18" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 23 23">
            <path fill="#f35325" d="M1 1h10v10H1z"/>
            <path fill="#81bc06" d="M12 1h10v10H12z"/>
            <path fill="#05a6f0" d="M1 12h10v10H1z"/>
            <path fill="#ffba08" d="M12 12h10v10H12z"/>
          </svg>
        SVG
      else
        clavis_content_tag(:div, "", class: "clavis-icon clavis-icon-#{provider}")
      end
    end

    def clavis_auth_authorize_path(provider)
      # Explicitly add /auth prefix for direct calls
      "/auth/#{provider}"
    end

    # Rails helper methods for non-Rails environments
    def clavis_content_tag(tag, content_or_options_with_block = nil, options = nil, &)
      if block_given?
        options = content_or_options_with_block if content_or_options_with_block.is_a?(Hash)
        content = capture(&)
      else
        content = content_or_options_with_block
      end

      options ||= {}
      tag_options = clavis_tag_options(options)

      "<#{tag}#{tag_options}>#{content}</#{tag}>"
    end

    def clavis_link_to(name = nil, options = nil, html_options = nil, &)
      if block_given?
        html_options = options
        options = name
        name = capture(&)
      end
      options ||= {}
      html_options ||= {}

      url = clavis_url_for(options)
      html_options = clavis_convert_options_to_data_attributes(options, html_options)
      tag_options = clavis_tag_options(html_options)

      href = "href=\"#{url}\"" unless url.nil?
      "<a #{href}#{tag_options}>#{name}</a>"
    end

    def clavis_url_for(options)
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

    def clavis_tag_options(options)
      return "" if options.empty?

      attrs = []
      options.each_pair do |key, value|
        if key.to_s == "data" && value.is_a?(Hash)
          value.each_pair do |k, v|
            attrs << clavis_data_tag_option("data-#{k}", v)
          end
        elsif key.to_s == "class" && value.is_a?(Array)
          attrs << clavis_tag_option(key, value.join(" "))
        else
          attrs << clavis_tag_option(key, value)
        end
      end

      " #{attrs.join(" ")}" unless attrs.empty?
    end

    def clavis_tag_option(key, value)
      "#{key}=\"#{value}\""
    end

    def clavis_data_tag_option(key, value)
      "#{key}=\"#{value}\""
    end

    def clavis_convert_options_to_data_attributes(_options, html_options)
      html_options["data-method"] = html_options.delete(:method) if html_options.key?(:method)

      html_options
    end

    def clavis_capture
      yield
    end

    def controller_name
      "auth"
    end

    def action_name
      "index"
    end
  end
end
