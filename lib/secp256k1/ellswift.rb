module Secp256k1
  module EllSwift

    # Decode ellswift public key.
    # @param [String] ell_key ElligatorSwift key with binary format.
    # @param [Boolean] compressed Whether to compress the public key or not.
    # @return [String] Decoded public key with hex format.
    # @raise [Secp256k1::Error] If decode failed.
    # @raise [ArgumentError] If invalid arguments specified.
    def ellswift_decode(ell_key, compressed: true)
      validate_string!("ell_key", ell_key, ELL_SWIFT_KEY_SIZE)
      ell_key = hex2bin(ell_key)
      with_context do |context|
        ell64 = FFI::MemoryPointer.new(:uchar, ell_key.bytesize).put_bytes(0, ell_key)
        internal = FFI::MemoryPointer.new(:uchar, 64)
        result = secp256k1_ellswift_decode(context, internal, ell64)
        raise Error, 'Decode failed.' unless result == 1
        serialize_pubkey_internal(context, internal, compressed)
      end
    end

    # Compute an ElligatorSwift public key for a secret key.
    # @param [String] private_key private key with hex format
    # @return [String] ElligatorSwift public key with hex format.
    # @raise [Secp256k1::Error] If failed to create elligattor swhift public key.
    # @raise [ArgumentError] If invalid arguments specified.
    def ellswift_create(private_key)
      validate_string!("private_key", private_key, 32)
      private_key = hex2bin(private_key)
      with_context(flags: CONTEXT_SIGN) do |context|
        ell64 = FFI::MemoryPointer.new(:uchar, 64)
        seckey32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, private_key)
        result = secp256k1_ellswift_create(context, ell64, seckey32, nil)
        raise Error, 'Failed to create ElligatorSwift public key.' unless result == 1
        ell64.read_string(64).unpack1('H*')
      end
    end

    # Compute X coordinate of shared ECDH point between elswift pubkey and private_key.
    # @param [String] their_ell_pubkey Their EllSwift public key.
    # @param [String] our_ell_pubkey Our EllSwift public key.
    # @param [String] private_key private key with hex format.
    # @param [Boolean] initiating Whether your initiator or not.
    # @return [String] x coordinate with hex format.
    # @raise [Secp256k1::Error] If secret is invalid or hashfp return 0.
    def ellswift_ecdh_xonly(their_ell_pubkey, our_ell_pubkey, private_key, initiating)
      validate_string!("their_ell_pubkey", their_ell_pubkey, ELL_SWIFT_KEY_SIZE)
      validate_string!("our_ell_pubkey", our_ell_pubkey, ELL_SWIFT_KEY_SIZE)
      validate_string!("private_key", private_key, 32)
      their_ell_pubkey = hex2bin(their_ell_pubkey)
      our_ell_pubkey = hex2bin(our_ell_pubkey)
      private_key = hex2bin(private_key)

      with_context(flags: CONTEXT_SIGN) do |context|
        output = FFI::MemoryPointer.new(:uchar, 32)
        our_ell_ptr = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, our_ell_pubkey)
        their_ell_ptr = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, their_ell_pubkey)
        seckey32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, private_key)
        hashfp = C.ellswift_xdh_hash_function_bip324
        result = secp256k1_ellswift_xdh(context, output,
                                        initiating ? our_ell_ptr : their_ell_ptr,
                                        initiating ? their_ell_ptr : our_ell_ptr,
                                        seckey32,
                                        initiating ? 0 : 1,
                                        hashfp, nil)
        raise Error, "secret was invalid or hashfp returned 0." unless result == 1
        output.read_string(32).unpack1('H*')
      end
    end
  end
end