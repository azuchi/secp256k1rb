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
end