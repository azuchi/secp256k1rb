# frozen_string_literal: true

require 'spec_helper'
require 'digest'

RSpec.describe Secp256k1 do
  include_context "common setup"

  describe '#generate_key_pair' do
    context 'compressed' do
      subject { target.generate_key_pair }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        private_key = subject[0]
        public_key = subject[1]
        expect(private_key.length).to eq(64)
        # pubkey
        expect(public_key.length).to eq(66)
        expect(['02', '03'].include?(public_key[0...2])).to be true
        pubkey = target.generate_pubkey(private_key)
        expect(pubkey).to eq(public_key)
      end
    end

    context 'uncompressed' do
      subject { target.generate_key_pair(compressed: false) }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        private_key = subject[0]
        public_key = subject[1]
        # privkey
        expect(private_key.length).to eq(64)
        # pubkey
        expect(public_key.length).to eq(130)
        expect(public_key[0...2]).to eq('04')
        pubkey = target.generate_pubkey(private_key, compressed: false)
        expect(pubkey).to eq(public_key)
      end
    end
  end

  describe '#generate_pubkey' do
    subject { target.generate_pubkey(privkey, compressed: true) }

    let(:privkey) { '206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff' }

    it { is_expected.to eq '020025aeb645b64b632c91d135683e227cb508ebb1766c65ee40405f53b8f1bb3a' }
  end

  describe '#sign/#verify' do
    context 'ecdsa' do
      it 'should be signed' do
        message = Digest::SHA256.digest('message')
        priv_key = '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438'
        pub_key = '0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9'
        sig = target.sign_ecdsa(message, priv_key, nil)
        expect(target.verify_ecdsa(message, sig, pub_key)).to be true
        expect{target.verify_ecdsa('hoge', sig, pub_key)}.to raise_error(ArgumentError, 'data must be 32 bytes.')
      end
    end

    context 'schnorr' do
      it 'should be signed' do
        message = Digest::SHA256.digest('message')
        priv_key = '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438'
        pub_key = target.generate_pubkey(priv_key)
        sig = target.sign_schnorr(message, priv_key)
        expect(target.verify_schnorr(message, sig, pub_key[2..-1])).to be true
        expect{target.verify_schnorr('hoge', sig, pub_key[2..-1])}.to raise_error(ArgumentError, 'data must be 32 bytes.')

        # specify aux_rand
        message = ['7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'].pack('H*')
        priv_key = 'C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9'
        aux_rand = ['C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906'].pack('H*')
        sig = target.sign_schnorr(message, priv_key, aux_rand).unpack1('H*')
        expect(sig).to eq('5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7')
      end
    end
  end

  describe '#valid_xonly_pubkey' do
    context 'valid public key' do
      it 'should return true.' do
        expect(target.valid_xonly_pubkey?('92ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9')).to be true
      end
    end

    context 'invalid public key(not on curve)' do
      it 'should return false.' do
        expect(target.valid_xonly_pubkey?('0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9')).to be false
        expect(target.valid_xonly_pubkey?('00' * 32)).to be false
      end
    end
  end

  describe '#ecdsa_signature_to_compact/#ecdsa_signature_from_compact' do
    it 'round-trips between DER and compact signatures' do
      sk, pk = target.generate_key_pair
      msg = Digest::SHA256.digest('message')
      der = target.sign_ecdsa(msg, sk)
      compact = target.ecdsa_signature_to_compact(der)
      expect(compact.bytesize).to eq(64)
      der2 = target.ecdsa_signature_from_compact(compact)
      expect(target.verify_ecdsa(msg, der2, pk)).to be true
    end

    it 'raises ArgumentError for invalid arguments' do
      expect { target.ecdsa_signature_to_compact(123) }.to raise_error(ArgumentError)
      expect { target.ecdsa_signature_from_compact('aa') }.to raise_error(ArgumentError)
    end
  end

  describe '#tagged_sha256' do
    it 'matches the BIP-340 tagged hash definition' do
      tag = 'BIP0340/challenge'
      msg = SecureRandom.bytes(37)
      tag_hash = Digest::SHA256.digest(tag)
      expected = Digest::SHA256.hexdigest(tag_hash + tag_hash + msg)
      expect(target.tagged_sha256(tag, msg)).to eq(expected)
    end

    it 'handles empty messages' do
      tag = 'tag'
      tag_hash = Digest::SHA256.digest(tag)
      expect(target.tagged_sha256(tag, '')).to eq(Digest::SHA256.hexdigest(tag_hash + tag_hash))
    end

    it 'raises ArgumentError for invalid arguments' do
      expect { target.tagged_sha256(123, 'msg') }.to raise_error(ArgumentError)
    end
  end

  describe '#sign_schnorr_custom' do
    it 'matches sign_schnorr for 32-byte messages' do
      sk, _ = target.generate_key_pair
      msg = Digest::SHA256.digest('message')
      aux = SecureRandom.bytes(32)
      expect(target.sign_schnorr_custom(msg, sk, aux)).to eq(target.sign_schnorr(msg, sk, aux))
    end

    it 'signs and verifies variable-length messages' do
      sk, pk = target.generate_key_pair
      xonly, = target.xonly_pubkey_from_pubkey(pk)
      msg = 'a' * 100
      sig = target.sign_schnorr_custom(msg, sk)
      expect(sig.bytesize).to eq(64)
      expect(target.verify_schnorr_custom(msg, sig, xonly)).to be true
      expect(target.verify_schnorr_custom('b' * 100, sig, xonly)).to be false
    end
  end

end