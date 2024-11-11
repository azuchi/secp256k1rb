# frozen_string_literal: true

require 'spec_helper'
require 'digest'

RSpec.describe Secp256k1 do

  let(:target) {
    class Target
      include Secp256k1
    end.new
  }

  describe '#generate_key_pair' do
    context 'compressed' do
      subject { target.generate_key_pair }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        # privkey
        expect(subject[0].length).to eq(64)
        # pubkey
        expect(subject[1].length).to eq(66)
        expect(['02', '03'].include?(subject[1][0...2])).to be true
      end
    end

    context 'uncompressed' do
      subject { target.generate_key_pair(compressed: false) }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        # privkey
        expect(subject[0].length).to eq(64)
        # pubkey
        expect(subject[1].length).to eq(130)
        expect(subject[1][0...2]).to eq('04')
      end
    end
  end

  describe '#generate_pubkey' do
    subject { target.generate_pubkey(privkey, compressed: true) }

    let(:privkey) { '206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff' }

    it { is_expected.to eq '020025aeb645b64b632c91d135683e227cb508ebb1766c65ee40405f53b8f1bb3a' }
  end

  describe '#sign_data/#verify_data' do
    context 'ecdsa' do
      it 'should be signed' do
        message = Digest::SHA256.digest('message')
        priv_key = '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438'
        pub_key = '0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9'
        sig = target.sign_data(message, priv_key, nil)
        expect(target.verify_sig(message, sig, pub_key)).to be true
        expect{target.verify_sig('hoge', sig, pub_key)}.to raise_error(ArgumentError, 'data must be 32 bytes.')
      end
    end

    context 'schnorr' do
      it 'should be signed' do
        message = Digest::SHA256.digest('message')
        priv_key = '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438'
        pub_key = target.generate_pubkey(priv_key)
        sig = target.sign_data(message, priv_key, algo: :schnorr)
        expect(target.verify_sig(message, sig, pub_key[2..-1], algo: :schnorr)).to be true
        expect{target.verify_sig('hoge', sig, pub_key[2..-1], algo: :schnorr)}.to raise_error(ArgumentError, 'data must be 32 bytes.')

        # specify aux_rand
        message = ['7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'].pack('H*')
        priv_key = 'C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9'
        aux_rand = ['C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906'].pack('H*')
        sig = target.sign_data(message, priv_key, aux_rand, algo: :schnorr).unpack1('H*')
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

end