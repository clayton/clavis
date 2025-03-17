# frozen_string_literal: true

require "rails"

RSpec.describe Clavis::AuthController, type: :controller, rails: true do
  # This is a stub test since we can't fully test the controller without a Rails app
  it "includes the Authentication concern" do
    expect(described_class.included_modules).to include(Clavis::Controllers::Concerns::Authentication)
  end
end
