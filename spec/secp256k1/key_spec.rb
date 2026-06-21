require 'spec_helper'

RSpec.describe Secp256k1::Key do
  include_context "common setup"

  let(:key_pair) { target.generate_key_pair }
  let(:private_key) { key_pair[0] }
  let(:public_key) { key_pair[1] }
  let(:tweak) { SecureRandom.bytes(32).unpack1('H*') }

  describe '#tweak_add_seckey/#tweak_add_pubkey' do
    it 'is consistent with public key derivation' do
      tweaked_sk = target.tweak_add_seckey(private_key, tweak)
      tweaked_pk = target.tweak_add_pubkey(public_key, tweak)
      expect(target.generate_pubkey(tweaked_sk)).to eq(tweaked_pk)
    end

    it 'raises ArgumentError for invalid arguments' do
      expect { target.tweak_add_seckey(private_key, 'aa') }.to raise_error(ArgumentError)
      expect { target.tweak_add_pubkey(123, tweak) }.to raise_error(ArgumentError)
    end
  end

  describe '#tweak_mul_seckey/#tweak_mul_pubkey' do
    it 'is consistent with public key derivation' do
      tweaked_sk = target.tweak_mul_seckey(private_key, tweak)
      tweaked_pk = target.tweak_mul_pubkey(public_key, tweak)
      expect(target.generate_pubkey(tweaked_sk)).to eq(tweaked_pk)
    end
  end

  describe '#negate_seckey/#negate_pubkey' do
    it 'returns the original key when negated twice' do
      expect(target.negate_seckey(target.negate_seckey(private_key))).to eq(private_key)
      expect(target.negate_pubkey(target.negate_pubkey(public_key))).to eq(public_key)
    end
  end

  describe '#combine_pubkeys' do
    it 'equals the public key of the summed private keys' do
      sk2, pk2 = target.generate_key_pair
      combined = target.combine_pubkeys([public_key, pk2])
      sum_sk = target.tweak_add_seckey(private_key, sk2)
      expect(combined).to eq(target.generate_pubkey(sum_sk))
    end

    it 'raises ArgumentError for invalid arguments' do
      expect { target.combine_pubkeys([]) }.to raise_error(ArgumentError)
      expect { target.combine_pubkeys(public_key) }.to raise_error(ArgumentError)
    end
  end

  describe '#xonly_pubkey_from_pubkey' do
    subject { target.xonly_pubkey_from_pubkey(public_key) }
    it 'returns a 32-byte x-only public key and its parity' do
      xonly, parity = subject
      expect([xonly].pack('H*').bytesize).to eq(32)
      expect([0, 1]).to include(parity)
      expect(target.valid_xonly_pubkey?(xonly)).to be true
    end
  end

  describe '#xonly_tweak_add_pubkey/#xonly_tweak_add_check?' do
    it 'verifies a tweaked x-only public key' do
      xonly, = target.xonly_pubkey_from_pubkey(public_key)
      full_tweaked, parity = target.xonly_tweak_add_pubkey(xonly, tweak)
      tweaked_xonly, = target.xonly_pubkey_from_pubkey(full_tweaked)
      expect(target.xonly_tweak_add_check?(tweaked_xonly, parity, xonly, tweak)).to be true
    end

    it 'returns false for a wrong tweak' do
      xonly, = target.xonly_pubkey_from_pubkey(public_key)
      full_tweaked, parity = target.xonly_tweak_add_pubkey(xonly, tweak)
      tweaked_xonly, = target.xonly_pubkey_from_pubkey(full_tweaked)
      wrong = SecureRandom.bytes(32).unpack1('H*')
      expect(target.xonly_tweak_add_check?(tweaked_xonly, parity, xonly, wrong)).to be false
    end
  end

  describe 'key pair accessors' do
    let(:keypair) { target.create_keypair(private_key) }
    it 'extracts the private key, public key and x-only public key' do
      expect(target.keypair_to_seckey(keypair)).to eq(private_key)
      expect(target.keypair_to_pubkey(keypair)).to eq(public_key)
      xonly, parity = target.keypair_to_xonly_pubkey(keypair)
      expect(target.xonly_pubkey_from_pubkey(public_key)).to eq([xonly, parity])
    end
  end

  describe '#compare_pubkey/#sort_pubkeys' do
    let(:pubkeys) { 5.times.map { target.generate_key_pair[1] } }

    it 'returns 0 for equal public keys' do
      expect(target.compare_pubkey(public_key, public_key)).to eq(0)
    end

    it 'sorts public keys in lexicographic order consistent with compare_pubkey' do
      sorted = target.sort_pubkeys(pubkeys)
      expect(sorted.sort).to eq(pubkeys.sort)
      sorted.each_cons(2) do |a, b|
        expect(target.compare_pubkey(a, b)).to be <= 0
      end
    end

    it 'raises ArgumentError for invalid arguments' do
      expect { target.sort_pubkeys([]) }.to raise_error(ArgumentError)
      expect { target.compare_pubkey(public_key, 123) }.to raise_error(ArgumentError)
    end
  end

  describe '#compare_xonly_pubkey' do
    it 'returns 0 for equal keys and matches byte order otherwise' do
      xonly1, = target.xonly_pubkey_from_pubkey(public_key)
      xonly2, = target.xonly_pubkey_from_pubkey(target.generate_key_pair[1])
      expect(target.compare_xonly_pubkey(xonly1, xonly1)).to eq(0)
      expect(target.compare_xonly_pubkey(xonly1, xonly2) <=> 0).to eq(xonly1 <=> xonly2)
    end
  end

  describe '#keypair_xonly_tweak_add' do
    it 'is consistent with xonly_tweak_add_pubkey' do
      keypair = target.create_keypair(private_key)
      xonly, = target.xonly_pubkey_from_pubkey(public_key)
      tweaked_keypair = target.keypair_xonly_tweak_add(keypair, tweak)
      tweaked_xonly, = target.keypair_to_xonly_pubkey(tweaked_keypair)
      full_tweaked, = target.xonly_tweak_add_pubkey(xonly, tweak)
      expected_xonly, = target.xonly_pubkey_from_pubkey(full_tweaked)
      expect(tweaked_xonly).to eq(expected_xonly)
    end
  end
end
