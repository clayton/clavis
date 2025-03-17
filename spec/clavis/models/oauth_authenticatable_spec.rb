# frozen_string_literal: true

require "spec_helper"

RSpec.describe Clavis::Models::OauthAuthenticatable do
  it "is aliased to Clavis::Models::Concerns::OauthAuthenticatable" do
    expect(described_class).to eq(Clavis::Models::Concerns::OauthAuthenticatable)
  end

  it "has the same methods as Clavis::Models::Concerns::OauthAuthenticatable" do
    concern_methods = Clavis::Models::Concerns::OauthAuthenticatable.instance_methods(false)
    alias_methods = described_class.instance_methods(false)

    expect(alias_methods).to match_array(concern_methods)
  end
end
