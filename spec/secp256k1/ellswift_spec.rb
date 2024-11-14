require 'spec_helper'

RSpec.describe Secp256k1::EllSwift do
  include_context "common setup"

  let(:decode_vectors) { read_csv('ellswift_decode_test_vectors.csv') }

  describe 'test vectors' do
    it do
      # Decode
      decode_vectors.each do |v|
        key = target.ellswift_decode(v['ellswift'])
        expect(key[2..-1]).to eq(v['x'])
      end

      # Create
      key1 = target.ellswift_create('12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747')
      key2 = target.ellswift_create('b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117')
      expect(target.ellswift_decode(key1)).
        to eq('030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744')
      expect(target.ellswift_decode(key2)).
        to eq('03183905ae25e815634ce7f5d9bedbaa2c39032ab98c75b5e88fe43f8dd8246f3c')
      expect(target.ellswift_decode(key1, compressed: false)).
        to eq('040b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a7447b5f0bba9e01e6fe4735c8383e6e7a3347a0fd72381b8f797a19f694054e5a69')
      expect(target.ellswift_decode(key2, compressed: false)).
        to eq('04183905ae25e815634ce7f5d9bedbaa2c39032ab98c75b5e88fe43f8dd8246f3c5473ccd4ab475e6a9e6620b52f5ce2fd15a2de32cbe905154b3a05844af70785')
    end
  end
end