# frozen_string_literal: true

require "rails"

RSpec.describe Clavis::Engine, rails: true do
  it "is a Rails::Engine" do
    expect(described_class.superclass).to eq(Rails::Engine)
  end

  it "isolates the namespace" do
    expect(described_class.isolated?).to be true
  end
end
