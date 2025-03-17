# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Security::InputValidator" do
  before do
    # Reset configuration before each test
    Clavis.reset_configuration!
  end

  describe "URL validation" do
    it "validates URLs" do
      # Valid URLs
      expect(Clavis::Security::InputValidator.valid_url?("https://example.com")).to be true
      expect(Clavis::Security::InputValidator.valid_url?("https://example.com/path?query=value")).to be true

      # Invalid URLs
      expect(Clavis::Security::InputValidator.valid_url?("not-a-url")).to be false
      expect(Clavis::Security::InputValidator.valid_url?("javascript:alert(1)")).to be false
      expect(Clavis::Security::InputValidator.valid_url?("data:text/html,<script>alert(1)</script>")).to be false
    end

    it "validates URLs with allowed schemes" do
      # Valid URLs with allowed schemes
      expect(Clavis::Security::InputValidator.valid_url?("https://example.com", allowed_schemes: ["https"])).to be true
      expect(Clavis::Security::InputValidator.valid_url?("http://example.com",
                                                         allowed_schemes: %w[http https])).to be true

      # Invalid URLs with disallowed schemes
      expect(Clavis::Security::InputValidator.valid_url?("http://example.com", allowed_schemes: ["https"])).to be false
      expect(Clavis::Security::InputValidator.valid_url?("ftp://example.com",
                                                         allowed_schemes: %w[http https])).to be false
    end
  end

  describe "token validation" do
    it "validates OAuth tokens" do
      # Valid tokens
      expect(Clavis::Security::InputValidator.valid_token?("valid_token_123")).to be true
      expect(Clavis::Security::InputValidator.valid_token?("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")).to be true

      # Invalid tokens
      expect(Clavis::Security::InputValidator.valid_token?(nil)).to be false
      expect(Clavis::Security::InputValidator.valid_token?("")).to be false
      expect(Clavis::Security::InputValidator.valid_token?("<script>alert(1)</script>")).to be false
    end
  end

  describe "code validation" do
    it "validates authorization codes" do
      # Valid codes
      expect(Clavis::Security::InputValidator.valid_code?("valid_code_123")).to be true

      # Invalid codes
      expect(Clavis::Security::InputValidator.valid_code?(nil)).to be false
      expect(Clavis::Security::InputValidator.valid_code?("")).to be false
      expect(Clavis::Security::InputValidator.valid_code?("<script>alert(1)</script>")).to be false
    end
  end

  describe "state validation" do
    it "validates state parameters" do
      # Valid state
      expect(Clavis::Security::InputValidator.valid_state?("valid_state_123")).to be true

      # Invalid state
      expect(Clavis::Security::InputValidator.valid_state?(nil)).to be false
      expect(Clavis::Security::InputValidator.valid_state?("")).to be false
      expect(Clavis::Security::InputValidator.valid_state?("<script>alert(1)</script>")).to be false
    end
  end

  describe "API response validation" do
    it "validates token responses" do
      # Valid token response
      valid_response = {
        "access_token" => "valid_token_123",
        "token_type" => "Bearer",
        "expires_in" => 3600,
        "refresh_token" => "valid_refresh_token_123"
      }
      expect(Clavis::Security::InputValidator.valid_token_response?(valid_response)).to be true

      # Invalid token response
      invalid_response = {
        "error" => "invalid_request",
        "error_description" => "Invalid request"
      }
      expect(Clavis::Security::InputValidator.valid_token_response?(invalid_response)).to be false

      # Missing required fields
      missing_fields_response = {
        "token_type" => "Bearer",
        "expires_in" => 3600
      }
      expect(Clavis::Security::InputValidator.valid_token_response?(missing_fields_response)).to be false

      # Malicious response
      malicious_response = {
        "access_token" => "<script>alert(1)</script>",
        "token_type" => "Bearer",
        "expires_in" => 3600
      }
      expect(Clavis::Security::InputValidator.valid_token_response?(malicious_response)).to be false
    end

    it "validates userinfo responses" do
      # Valid userinfo response
      valid_response = {
        "sub" => "123456789",
        "name" => "John Doe",
        "email" => "john@example.com"
      }
      expect(Clavis::Security::InputValidator.valid_userinfo_response?(valid_response)).to be true

      # Invalid userinfo response
      invalid_response = {
        "error" => "invalid_token",
        "error_description" => "Invalid token"
      }
      expect(Clavis::Security::InputValidator.valid_userinfo_response?(invalid_response)).to be false

      # Missing required fields
      missing_fields_response = {
        "name" => "John Doe",
        "email" => "john@example.com"
      }
      expect(Clavis::Security::InputValidator.valid_userinfo_response?(missing_fields_response)).to be false

      # Malicious response
      malicious_response = {
        "sub" => "123456789",
        "name" => "<script>alert(1)</script>",
        "email" => "john@example.com"
      }
      expect(Clavis::Security::InputValidator.valid_userinfo_response?(malicious_response)).to be false
    end
  end

  describe "sanitization" do
    it "sanitizes strings" do
      # Test sanitization
      expect(Clavis::Security::InputValidator.sanitize("<script>alert(1)</script>")).to eq("")
      expect(Clavis::Security::InputValidator.sanitize("Valid text")).to eq("Valid text")
      expect(Clavis::Security::InputValidator.sanitize("Text with <b>HTML</b>")).to eq("Text with HTML")
    end

    it "sanitizes hashes" do
      # Test hash sanitization
      input_hash = {
        "name" => "<script>alert(1)</script>",
        "email" => "john@example.com",
        "nested" => {
          "value" => "<img src=x onerror=alert(1)>"
        }
      }

      sanitized_hash = Clavis::Security::InputValidator.sanitize_hash(input_hash)

      expect(sanitized_hash["name"]).to eq("")
      expect(sanitized_hash["email"]).to eq("john@example.com")
      expect(sanitized_hash["nested"]["value"]).to eq("")
    end
  end
end
