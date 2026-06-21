require 'spec_helper'

RSpec.describe Secp256k1::ECDH do
  include_context "common setup"

  describe '#ecdh' do
    it 'computes the same shared secret for both parties' do
      alice_sk, alice_pk = target.generate_key_pair
      bob_sk, bob_pk = target.generate_key_pair
      shared_a = target.ecdh(bob_pk, alice_sk)
      shared_b = target.ecdh(alice_pk, bob_sk)
      expect(shared_a).to eq(shared_b)
      expect([shared_a].pack('H*').bytesize).to eq(32)
    end

    it 'raises ArgumentError for invalid arguments' do
      _, pk = target.generate_key_pair
      expect { target.ecdh(pk, 'aa') }.to raise_error(ArgumentError)
      expect { target.ecdh(123, 'aa' * 32) }.to raise_error(ArgumentError)
    end

    it 'produces the same secret with the explicit default hash functions' do
      sk, _ = target.generate_key_pair
      _, pk = target.generate_key_pair
      default_secret = target.ecdh(pk, sk)
      expect(target.ecdh(pk, sk, hash_function: Secp256k1::C.ecdh_hash_function_sha256)).to eq(default_secret)
      expect(target.ecdh(pk, sk, hash_function: Secp256k1::C.ecdh_hash_function_default)).to eq(default_secret)
    end
  end
end
