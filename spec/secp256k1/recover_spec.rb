require 'spec_helper'
require 'securerandom'

RSpec.describe Secp256k1::Recover do
  include_context "common setup"

  describe 'sign and recover' do
    it do
      50.times do
        compressed = true
        private_key, public_key = target.generate_key_pair(compressed: compressed)
        digest = SecureRandom.random_bytes(32)
        sig, rec = target.sign_recoverable(digest, private_key)
        full_sig = [rec + 0x1b + 4].pack('C') + [sig].pack('H*')
        recover_pubkey = target.recover(digest, full_sig, compressed)
        expect(recover_pubkey).to eq(public_key)
      end
    end
  end

  describe '#recoverable_signature_to_ecdsa' do
    it 'converts a recoverable signature into a verifiable ECDSA signature' do
      private_key, public_key = target.generate_key_pair
      digest = SecureRandom.random_bytes(32)
      sig, rec = target.sign_recoverable(digest, private_key)
      full_sig = [rec + 0x1b + 4].pack('C') + [sig].pack('H*')
      der = target.recoverable_signature_to_ecdsa(full_sig)
      expect(target.verify_ecdsa(digest, der, public_key)).to be true
    end

    it 'raises ArgumentError for invalid arguments' do
      expect { target.recoverable_signature_to_ecdsa('aa') }.to raise_error(ArgumentError)
    end
  end
end