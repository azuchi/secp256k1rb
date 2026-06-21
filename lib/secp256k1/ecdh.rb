module Secp256k1
  # ECDH module.
  # @example
  #   include Secp256k1
  #
  #   alice_sk, alice_pk = generate_key_pair
  #   bob_sk, bob_pk = generate_key_pair
  #
  #   # Both parties compute the same shared secret.
  #   ecdh(bob_pk, alice_sk) == ecdh(alice_pk, bob_sk)
  #
  module ECDH

    # Compute an EC Diffie-Hellman shared secret.
    # @param [String] pubkey the other party's public key with hex format.
    # @param [String] private_key your private key with hex format.
    # @param [FFI::Pointer] hash_function (Optional)A pointer to the hash function to use. If omitted, the
    #   library default(SHA256 of the compressed point) is used. See {Secp256k1::C.ecdh_hash_function_sha256}.
    # @return [String] 32-byte shared secret with hex format.
    # @raise [Secp256k1::Error] If the secret was invalid or the public key could not be parsed.
    # @raise [ArgumentError] If invalid arguments specified.
    def ecdh(pubkey, private_key, hash_function: nil)
      raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
      validate_string!("private_key", private_key, 32)
      pubkey = hex2bin(pubkey)
      private_key = hex2bin(private_key)
      with_context do |context|
        internal = parse_pubkey_internal(context, pubkey)
        seckey = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, private_key)
        output = FFI::MemoryPointer.new(:uchar, 32)
        hashfp = hash_function || FFI::Pointer::NULL
        raise Error, 'secp256k1_ecdh failed.' unless secp256k1_ecdh(context, output, internal, seckey, hashfp, nil) == 1
        output.read_string(32).unpack1('H*')
      end
    end
  end
end
