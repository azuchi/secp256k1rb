require 'spec_helper'
require 'digest'

RSpec.describe Secp256k1::MuSig do
  include_context "common setup"

  let(:pubkeys) { vector['pubkeys'] }
  let(:sk) { vector['sk'] }
  let(:sec_nonces) { vector['secnonces'] }
  let(:pub_nonces) { vector['pnonces'] }
  let(:agg_nonces) { vector['aggnonces'] }
  let(:msgs) { vector['msgs'] }
  let(:plain_tweak) { '7468697320636f756c64206265206120424950333220747765616b2e2e2e2e00' }
  let(:xonly_tweak) { '7468697320636f756c64206265206120546170726f6f7420747765616b2e2e00' }

  describe 'key_agg_vectors' do
    let(:vector) {  read_json('key_agg_vectors.json') }
    context 'valid case' do
      it do
        vector['valid_test_cases'].each do |keys|
          pubkey_candidates = keys['key_indices'].map{|i| pubkeys[i] }
          agg_key_ctx = target.aggregate_pubkey(pubkey_candidates)
          expect(agg_key_ctx).to be_a(Secp256k1::MuSig::KeyAggContext)
          expect(agg_key_ctx.aggregate_public_key).to eq(keys['expected'].downcase)
        end
      end
    end
    context 'error case' do
      it do
        tweaks = vector['tweaks']
        vector['error_test_cases'].each do |error|
          pubkey_candidates = error['key_indices'].map{|i| pubkeys[i] }
          if error['error']['type'] == 'invalid_contribution'
            expect{target.aggregate_pubkey(pubkey_candidates)}.to raise_error(Secp256k1::Error)
          else
            agg_key_ctx = target.aggregate_pubkey(pubkey_candidates)
            # error['tweak_indices'].each do |index|
            #   tweak = tweaks[index]
            #   is_xonly = error['is_xonly'][index]
            #   expect{agg_key_ctx.apply_tweak(tweak, is_xonly)}.to raise_error(ArgumentError, error['error']['comment'])
            # end
          end
        end
      end
    end
  end

  describe '#aggregate_musig_nonce' do
    let(:vector) { read_json('nonce_agg_vectors.json') }
    it do
      vector['valid_test_cases'].each do |valid|
        target_pub_nonces = valid['pnonce_indices'].map {|i|pub_nonces[i]}
        expect(target.aggregate_musig_nonce(target_pub_nonces)).to eq(valid['expected'].downcase)
      end
      vector['error_test_cases'].each do |valid|
        target_pub_nonces = valid['pnonce_indices'].map {|i|pub_nonces[i]}
        expect{target.aggregate_musig_nonce(target_pub_nonces)}.to raise_error(Secp256k1::Error)
      end
    end
  end

  describe "#tweak_add" do
    it do
      pubkey1 = '03daab525533167d7c47ffd9103a7dd93bbb3849683b74293d0f83d9512438a359'
      pubkey2 = '03f6168a914edad34a8c0b39e687f086aa999068b542f1f9457479baf63ff091d2'
      keys = [pubkey1, pubkey2]
      key_agg_ctx = target.aggregate_pubkey(keys)
      key_agg_ctx.tweak_add(plain_tweak)
      tweaked = key_agg_ctx.tweak_add(xonly_tweak, xonly: true)
      agg_pubkey = key_agg_ctx.aggregate_public_key
      expect(agg_pubkey).to eq(tweaked)
      expect(agg_pubkey).to eq("bddba4bdf75f1d95695b4851938ce2139c79c0e291c5f0e9ec901ed6ae9859cd")
    end
  end

  describe "sign and verify" do
    it do
      n_signers = 3
      msg = Digest::SHA256.digest('message')

      signers_key = n_signers.times.map do
        target.generate_key_pair
      end
      sorted_keys = signers_key.sort{|a, b| a[1] <=> b[1]}
      sorted_pubkeys = sorted_keys.map{|k|k[1]}
      sorted_private_keys = sorted_keys.map{|k|k[0]}
      key_agg_ctx = target.aggregate_pubkey(sorted_pubkeys)

      key_agg_ctx.tweak_add(plain_tweak)
      tweaked = key_agg_ctx.tweak_add(xonly_tweak, xonly: true)
      agg_pubkey = key_agg_ctx.aggregate_public_key
      expect(agg_pubkey).to eq(tweaked)

      nonce_pairs = n_signers.times.map do |i|
        session_id = target.generate_musig_session_id
        target.generate_musig_nonce(
          session_id,
          sorted_pubkeys[i],
          sk: sorted_private_keys[i],
          key_agg_ctx: key_agg_ctx,
          msg: msg
        )
      end

      pub_nonces = nonce_pairs.map{|p|p[1]}
      agg_nonce = target.aggregate_musig_nonce(pub_nonces)
      musig_session = Secp256k1::MuSig::Session.new(key_agg_ctx, agg_nonce, msg)

      partial_sigs = n_signers.times.map do |i|
        partial_sig = musig_session.partial_sign(nonce_pairs[i][0], sorted_keys[i][0])
        expect(musig_session.verify_partial_sig(partial_sig, nonce_pairs[i][1], sorted_keys[i][1])).to be true
        dummy_pubkey = target.generate_key_pair[1]
        expect(musig_session.verify_partial_sig(partial_sig, nonce_pairs[i][1], dummy_pubkey)).to be false
        partial_sig
      end

      agg_sig = musig_session.aggregate_partial_sigs(partial_sigs)
      expect(target.verify_schnorr(msg, agg_sig, agg_pubkey)).to be true
      expect(target.verify_schnorr(msg, agg_sig, sorted_keys[0][1][2..-1])).to be false
    end
  end
end
