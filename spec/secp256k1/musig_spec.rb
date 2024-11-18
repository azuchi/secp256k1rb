require 'spec_helper'

RSpec.describe Secp256k1::MuSig do
  include_context "common setup"

  let(:agg_vectors) { read_json('nonce_agg_vectors.json') }

  describe '#aggregate_nonce' do
    it do
      pub_nonces = agg_vectors['pnonces']
      agg_vectors['valid_test_cases'].each do |valid|
        target_pub_nonces = valid['pnonce_indices'].map {|i|pub_nonces[i]}
        expect(target.aggregate_nonce(target_pub_nonces)).to eq(valid['expected'].downcase)
      end
      agg_vectors['error_test_cases'].each do |valid|
        target_pub_nonces = valid['pnonce_indices'].map {|i|pub_nonces[i]}
        expect{target.aggregate_nonce(target_pub_nonces)}.to raise_error(Secp256k1::Error)
      end
    end
  end
end
