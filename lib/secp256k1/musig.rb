require_relative 'musig/key_agg'
require_relative 'musig/session'

module Secp256k1

  # MuSig module
  # @example
  #   include Secp256k1
  #
  #   # Two signer.
  #   sk1, pk1 = generate_key_pair
  #   sk2, pk2 = generate_key_pair
  #
  #   # Aggregate public key
  #   key_agg_ctx = aggregate_pubkey([pk1, pk2])
  #   agg_pubkey = key_agg_ctx.aggregate_public_key
  #
  #   # If you need tweak
  #   key_agg_ctx.tweak_add('7468697320636f756c64206265206120424950333220747765616b2e2e2e2e00')
  #   # If you need tweak with xonly
  #   key_agg_ctx.tweak_add('7468697320636f756c64206265206120546170726f6f7420747765616b2e2e00', xonly: true)
  #
  #   agg_pubkey = key_agg_ctx.aggregate_public_key
  #
  #   msg = Digest::SHA256.digest('message')
  #
  #   # Nonce generation
  #   session_id1 = generate_musig_session_id
  #   secnonce1, pubnonce1 = target.generate_musig_nonce(
  #     session_id1,
  #     pk1,
  #     sk: sk1,
  #     key_agg_ctx: key_agg_ctx,
  #     msg: msg
  #   )
  #
  #   session_id2 = generate_musig_session_id
  #   secnonce2, pubnonce2 = target.generate_musig_nonce(
  #     session_id2,
  #     pk2,
  #     sk: sk2,
  #     key_agg_ctx: key_agg_ctx,
  #     msg: msg
  #   )
  #
  #   # Aggregate public nonces
  #   agg_nonce = aggregate_musig_nonce([pubnonce1, pubnonce2])
  #
  #   # Generate partial sig
  #   musig_session = Secp256k1::MuSig::Session.new(key_agg_ctx, agg_nonce, msg)
  #   partial_sig1 = musig_session.partial_sign(secnonce1, sk1)
  #   partial_sig2 = musig_session.partial_sign(secnonce2, sk2)
  #
  #   # Aggregate signature
  #   agg_sig = musig_session.aggregate_partial_sigs([partial_sig1, partial_sig2])
  #
  #   # Verify schnorr signature
  #   verify_schnorr(msg, agg_sig, agg_pubkey)
  module MuSig

    # Aggregate public keys.
    # @param [Array] pubkeys An array of public keys.
    # @return [Secp2561k::MuSig::KeyAggContext]
    # @raise [Secp256k1::Error]
    def aggregate_pubkey(pubkeys)
      raise ArgumentError, "pubkeys must be an array." unless pubkeys.is_a?(Array)
      with_context do |context|
        pubkeys_ptrs = pubkeys.map do |pubkey|
          pubkey = hex2bin(pubkey)
          validate_string!('pubkey', pubkey, 33)
          input = FFI::MemoryPointer.new(:uchar, 33).put_bytes(0, pubkey)
          pubkey_ptr = FFI::MemoryPointer.new(:uchar, 64)
          raise Error, "pubkey is invalid." unless secp256k1_ec_pubkey_parse(context, pubkey_ptr, input, 33) == 1
          pubkey_ptr
        end
        pubkeys_ptr = FFI::MemoryPointer.new(:pointer, pubkeys.length)
        pubkeys_ptr.write_array_of_pointer(pubkeys_ptrs)
        agg_pubkey = FFI::MemoryPointer.new(:uchar, 64)
        cache = Secp256k1::MuSig::KeyAggCache.new
        if secp256k1_musig_pubkey_agg(context, agg_pubkey, cache.pointer, pubkeys_ptr, pubkeys.length) == 0
          raise Error, "secp256k1_musig_pubkey_agg argument error."
        end
        Secp256k1::MuSig::KeyAggContext.new(cache)
      end
    end

    # Generate fresh session id for musig signing session.
    # @return [String] The session id.
    def generate_musig_session_id
      SecureRandom.random_bytes(32).unpack1('H*')
    end

    # Generate nonce pair.
    # @param [String] session_id The uniform random identifier for this session.
    # @param [String] pk The public key for which the partial signature is generated.
    # @param [String] sk (Optional) The private key for which the partial signature is generated.
    # @param [Secp256k1::MuSig::KeyAggContext] key_agg_ctx (Optional) The aggregated public key context.
    # @param [String] msg (Optional) The message to be signed.
    # @param [String] extra_in (Optional) The auxiliary input.
    # @return [Array(String)] The array of secret nonce and public nonce with hex format.
    # @raise [ArgumentError] If invalid arguments specified.
    # @raise [Secp256k1::Error]
    def generate_musig_nonce(session_id, pk, sk: nil, key_agg_ctx: nil, msg: nil, extra_in: nil)
      validate_string!("session_id", session_id, 32)
      validate_string!("pk", pk, 33)
      validate_string!("sk", sk, 32) if sk
      validate_string!("msg", msg, 32) if msg
      validate_string!("extra_in", extra_in, 32) if extra_in

      if key_agg_ctx
        raise ArgumentError, "key_agg must be Secp256k1::MuSig::KeyAggContext." unless key_agg_ctx.is_a?(KeyAggContext)
      end

      with_context do |context|
        pk_ptr = FFI::MemoryPointer.new(:uchar, 33).put_bytes(0, hex2bin(pk))
        pubkey = FFI::MemoryPointer.new(:uchar, 64)
        raise Error, "pk is invalid public key." unless secp256k1_ec_pubkey_parse(context, pubkey, pk_ptr, 33) == 1

        pubnonce = FFI::MemoryPointer.new(:uchar, 132)
        secnonce = FFI::MemoryPointer.new(:uchar, 132)
        seckey = sk ? FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hex2bin(sk)) : nil
        msg32 = msg ? FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hex2bin(msg)) : nil
        extra_input32 = extra_in ? FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hex2bin(extra_in)) : nil
        session_secrand32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hex2bin(session_id))

        raise Error, "arguments is invalid." unless secp256k1_musig_nonce_gen(
          context, secnonce, pubnonce, session_secrand32, seckey, pubkey, msg32, key_agg_ctx.pointer, extra_input32) == 1

        pub66 = FFI::MemoryPointer.new(:uchar, 66)
        secp256k1_musig_pubnonce_serialize(context, pub66, pubnonce)
        [secnonce.read_string(132).unpack1('H*'), pub66.read_string(66).unpack1('H*')]
      end
    end

    # Aggregates the nonces of all signers into a single nonce.
    # @param [Array] pub_nonces An array of public nonces sent by the signers.
    # @return [String] An aggregated public nonce.
    # @raise [Secp256k1::Error]
    # @raise [ArgumentError] If invalid arguments specified.
    def aggregate_musig_nonce(pub_nonces)
      raise ArgumentError, "pub_nonces must be Array." unless pub_nonces.is_a?(Array)

      with_context do |context|
        nonce_ptrs = pub_nonces.map do |pub_nonce|
          pub_nonce = hex2bin(pub_nonce)
          validate_string!("pub_nonce", pub_nonce, 66)
          in66 = FFI::MemoryPointer.new(:uchar, 66).put_bytes(0, pub_nonce)
          pub_nonce_ptr = FFI::MemoryPointer.new(:uchar, 132)
          if secp256k1_musig_pubnonce_parse(context, pub_nonce_ptr, in66) == 0
            raise Error, "secp256k1_musig_pubnonce_parse error."
          end
          pub_nonce_ptr
        end
        agg_nonce = FFI::MemoryPointer.new(:uchar, 132)
        pubnonces = FFI::MemoryPointer.new(:pointer, pub_nonces.length)
        pubnonces.write_array_of_pointer(nonce_ptrs)
        result = secp256k1_musig_nonce_agg(context, agg_nonce, pubnonces, pub_nonces.length)
        raise Error, "nonce aggregation failed." if result == 0
        out66 = FFI::MemoryPointer.new(:uchar, 66)
        secp256k1_musig_aggnonce_serialize(context, out66, agg_nonce)
        out66.read_string(66).unpack1("H*")
      end
    end
  end
end