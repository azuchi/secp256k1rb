require_relative 'musig/key_agg'

module Secp256k1
  module MuSig

    # Aggregate public keys.
    # @param [Array] pubkeys An array of public keys.
    # @return [Secp2561k::MuSig::KeyAggContext]
    def aggregate_pubkey(pubkeys)
      raise ArgumentError, "pubkeys must be an array." unless pubkeys.is_a?(Array)
      with_context do |context|
        pubkeys_ptrs = pubkeys.map do |pubkey|
          pubkey = hex2bin(pubkey)
          validate_string!('pubkey', pubkey, 33)
          input = FFI::MemoryPointer.new(:uchar, 33).put_bytes(0, pubkey)
          pubkey_ptr = FFI::MemoryPointer.new(:uchar, 64)
          raise Error, "pubkey is invalid public key." unless secp256k1_ec_pubkey_parse(context, pubkey_ptr, input, 33) == 1
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

    # Aggregates the nonces of all signers into a single nonce.
    # @param [Array] pub_nonces An array of public nonces sent by the signers.
    # @return [String] An aggregated public nonce.
    # @raise [Secp256k1::Error]
    # @raise [ArgumentError] If invalid arguments specified.
    def aggregate_nonce(pub_nonces)
      raise ArgumentError, "nonces must be Array." unless pub_nonces.is_a?(Array)

      with_context do |context|
        nonce_ptrs = pub_nonces.map do |pub_nonce|
          validate_string!("pub_nonce", pub_nonce, 66)
          pub_nonce = hex2bin(pub_nonce)
          in_ptr = FFI::MemoryPointer.new(:uchar, pub_nonce.bytesize).put_bytes(0, pub_nonce)
          out_ptr = FFI::MemoryPointer.new(:uchar, 132)
          result = secp256k1_musig_pubnonce_parse(context, out_ptr, in_ptr)
          raise Error, "pub_nonce parse failed." unless result == 1
          out_ptr
        end
        agg_nonce = FFI::MemoryPointer.new(:uchar, 132)
        pubnonces = FFI::MemoryPointer.new(:pointer, pub_nonces.length)
        pubnonces.write_array_of_pointer(nonce_ptrs)
        result = secp256k1_musig_nonce_agg(context, agg_nonce, pubnonces, pub_nonces.length)
        raise Error, "nonce aggregation failed." if result == 0

        serialized =  FFI::MemoryPointer.new(:uchar, 66)
        secp256k1_musig_aggnonce_serialize(context, serialized, agg_nonce)
        serialized.read_string(66).unpack1('H*')
      end
    end
  end
end