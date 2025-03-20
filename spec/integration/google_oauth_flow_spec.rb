# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Google OAuth Flow" do
  let(:auth_code) { "4/0AXEFSeXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" }
  let(:token_response) do
    {
      access_token: "ya29.a0AfB_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      expires_in: 3599,
      scope: "email profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid",
      token_type: "Bearer",
      id_token: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmNzI1NDEwMWY1NmU0MWNmMzVjOTkyNmZlaTE1MmQyYWFhOTNlMDgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyMjA4NjU3NzEzOTMtazFrNnFycGQ0ZnZ1dGNhYnVhbmVncTRmaHQwbDRubHQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyMjA4NjU3NzEzOTMtazFrNnFycGQ0ZnZ1dGNhYnVhbmVncTRmaHQwbDRubHQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI5Nzk0NjI3MTg5MDM5MzQ4MzMiLCJlbWFpbCI6ImV4YW1wbGVAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IllUUUcwZkE0RktYUE9xWEswT1FXd2ciLCJub25jZSI6ImE2N2NkZTM3OWEzNDEzODRmOTcwZTIxY2FlZGM5ZDkwIiwibmFtZSI6IkpvaG4gRG9lIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0laOFYyOE5rZ0NEVmRPRmZoTXBONFVxcXhHN3dydWFiOUtQeFkzRXFISz1zOTYtYyIsImdpdmVuX25hbWUiOiJKb2huIiwiZmFtaWx5X25hbWUiOiJEb2UiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTcxMDcyMTU4NywiZXhwIjoxNzEwNzI1MTg3fQ.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    }
  end
  let(:userinfo_response) do
    {
      sub: "112233445566778899000",
      name: "John Doe",
      given_name: "John",
      family_name: "Doe",
      picture: "https://example.com/profile_picture.jpg",
      email: "example@example.com",
      email_verified: true,
      locale: "en"
    }
  end

  before do
    # Configure Clavis
    Clavis.configure do |config|
      config.providers = {
        google: {
          client_id: "fake-client-id-123456789.apps.googleusercontent.com",
          client_secret: "fake-client-secret-XXXXXXXXXXXXXXXX",
          redirect_uri: "http://localhost:3000/auth/google/callback",
          verify_token: false # Disable token verification in tests
        }
      }
    end

    # Mock the HTTP client
    allow_any_instance_of(Faraday::Connection).to receive(:post)
      .with(
        "https://oauth2.googleapis.com/token",
        hash_including(code: auth_code)
      )
      .and_return(
        double(
          status: 200,
          body: token_response
        )
      )

    allow_any_instance_of(Faraday::Connection).to receive(:get)
      .and_return(
        double(
          status: 200,
          body: userinfo_response
        )
      )

    # Stub verify_token to always pass in tests
    allow_any_instance_of(Clavis::Providers::Google).to receive(:verify_token).and_return(true)
  end

  it "processes a Google OAuth callback successfully" do
    provider = Clavis.provider(:google)
    result = provider.process_callback(auth_code)

    expect(result).to be_a(Hash)
    expect(result[:provider]).to eq(:google)
    expect(result[:uid]).to eq("112233445566778899000")
    expect(result[:info]).to be_a(Hash)
    expect(result[:credentials]).to be_a(Hash)
    expect(result[:credentials][:token]).to eq(token_response[:access_token])
  end
end
