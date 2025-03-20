# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Clavis::Providers::Base response parsing" do
  let(:provider) do
    Clavis::Providers::Google.new(
      client_id: "fake-client-id",
      client_secret: "fake-client-secret",
      redirect_uri: "http://localhost:3000/auth/google/callback"
    )
  end

  before do
    # Disable token verification in tests
    allow_any_instance_of(Clavis::Providers::Google).to receive(:verify_token).and_return(true)
  end

  describe "#parse_token_response" do
    it "parses JSON string responses" do
      json_body = {
        access_token: "ya29.a0AfB_XXXX",
        expires_in: 3599,
        scope: "email profile",
        token_type: "Bearer"
      }.to_json

      response = double(body: json_body, status: 200)

      result = provider.send(:parse_token_response, response)
      expect(result).to be_a(Hash)
      expect(result[:access_token]).to eq("ya29.a0AfB_XXXX")
      expect(result[:token_type]).to eq("Bearer")
      expect(result[:expires_in]).to eq(3599)
      expect(result[:expires_at]).to be_a(Integer)
    end

    it "handles hash responses directly" do
      hash_body = {
        access_token: "ya29.a0AfB_XXXX",
        expires_in: 3599,
        scope: "email profile",
        token_type: "Bearer"
      }

      response = double(body: hash_body, status: 200)

      result = provider.send(:parse_token_response, response)
      expect(result).to be_a(Hash)
      expect(result[:access_token]).to eq("ya29.a0AfB_XXXX")
      expect(result[:token_type]).to eq("Bearer")
    end

    it "handles responses with string keys" do
      hash_body = {
        "access_token" => "ya29.a0AfB_XXXX",
        "expires_in" => 3599,
        "scope" => "email profile",
        "token_type" => "Bearer"
      }

      response = double(body: hash_body, status: 200)

      result = provider.send(:parse_token_response, response)
      expect(result).to be_a(Hash)
      expect(result[:access_token]).to eq("ya29.a0AfB_XXXX")
    end

    it "handles malformed response bodies gracefully" do
      bad_body = "not json"
      response = double(body: bad_body, status: 200)

      expect { provider.send(:parse_token_response, response) }.not_to raise_error
    end

    it "calculates expires_at from expires_in" do
      hash_body = {
        access_token: "ya29.a0AfB_XXXX",
        expires_in: 3600,
        token_type: "Bearer"
      }

      response = double(body: hash_body, status: 200)
      result = provider.send(:parse_token_response, response)

      expect(result[:expires_at]).to be > Time.now.to_i
      expect(result[:expires_at]).to be <= Time.now.to_i + 3601 # Allow for slight timing differences
    end
  end

  describe "#get_user_info" do
    let(:access_token) { "ya29.a0AfB_XXXX" }

    before do
      allow_any_instance_of(Faraday::Connection).to receive_message_chain(:get, :status).and_return(200)
    end

    it "handles hash response bodies" do
      user_info = {
        sub: "12345",
        name: "John Doe",
        email: "john@example.com"
      }

      allow_any_instance_of(Faraday::Connection).to receive_message_chain(:get, :body).and_return(user_info)

      result = provider.get_user_info(access_token)
      expect(result).to be_a(Hash)
      expect(result[:sub]).to eq("12345")
      expect(result[:name]).to eq("John Doe")
    end

    it "parses JSON string response bodies" do
      user_info = {
        sub: "12345",
        name: "John Doe",
        email: "john@example.com"
      }.to_json

      allow_any_instance_of(Faraday::Connection).to receive_message_chain(:get, :body).and_return(user_info)

      result = provider.get_user_info(access_token)
      expect(result).to be_a(Hash)
      expect(result[:sub]).to eq("12345")
    end

    it "handles error responses" do
      allow_any_instance_of(Faraday::Connection).to receive_message_chain(:get, :status).and_return(401)
      allow_any_instance_of(Faraday::Connection).to receive_message_chain(:get, :body).and_return({ error: "invalid_token" }.to_json)

      # The handler should raise an InvalidToken error
      expect { provider.get_user_info(access_token) }.to raise_error(Clavis::InvalidToken)
    end

    it "sanitizes dangerous content" do
      user_info = {
        sub: "12345",
        name: "<script>alert('XSS')</script>John Doe",
        email: "john@example.com"
      }

      allow_any_instance_of(Faraday::Connection).to receive_message_chain(:get, :body).and_return(user_info)

      result = provider.get_user_info(access_token)
      expect(result[:name]).not_to include("<script>")
    end
  end
end
