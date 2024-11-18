module Secp256k1
  module MuSig

    # Aggregates the nonces of all signers into a single nonce.
    # @param [Array] pub_nonces An array of public nonces sent by the signers.
    # @return [String] An aggregated public nonce.
    # @raise [Secp256k1::Error]
    # @raise [ArgumentError] If invalid arguments specified.
    def aggregate_nonce(pub_nonces)
      raise ArgumentError, "nonces must be Array." unless pub_nonces.is_a?(Array)

      with_context do |context|
        nonce_ptrs = pub_nonces.map do |pub_nonce|
          raise ArgumentError, "pub_nonce must be a String." unless pub_nonce.is_a?(String)
          pub_nonce = hex2bin(pub_nonce)
          raise ArgumentError, "pub_nonce must be 64 bytes." unless pub_nonce.bytesize == 66
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