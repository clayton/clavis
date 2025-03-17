# frozen_string_literal: true

require "rails"
require "generators/clavis/install_generator"

RSpec.describe Clavis::Generators::InstallGenerator, type: :generator, rails: true do
  # This is a stub test since we can't fully test the generator without a Rails app
  it "has a source root" do
    expect(described_class.source_root).not_to be_nil
  end

  it "has a providers option" do
    generator = described_class.new
    expect(generator.options).to have_key(:providers)
  end
end
