# frozen_string_literal: true

RSpec.describe Secp256k1 do
  it "has a version number" do
    expect(Secp256k1::VERSION).not_to be nil
  end
end
