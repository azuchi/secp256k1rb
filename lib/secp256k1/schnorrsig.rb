module Secp256k1
  # SchnorrSig module
  # @example
  #   include Secp256k1
  #
  #   sk, pk = generate_key_pair
  #
  #   # sign and verify (Schnorr)
  #   signature = sign_schnorr(msg, sk)
  #   verify_schnorr(msg, signature, pk[2..-1]) # public key must be 32 bytes
  #
  module SchnorrSig

    # Sign to data using schnorr.
    # @param [String] data The 32-byte message hash being signed with binary format.
    # @param [String] private_key a private key with hex format using sign.
    # @param [String] aux_rand The 32-byte extra entropy.
    # @return [String] signature data with binary format. If unsupported algorithm specified, return nil.
    # @raise [ArgumentError] If invalid arguments specified.
    def sign_schnorr(data, private_key, aux_rand = nil)
      validate_string!("data", data, 32)
      validate_string!("private_key", private_key, 32)
      validate_string!("aux_rand", aux_rand, 32) if aux_rand
      raise ArgumentError, "aux_rand must be String." if !aux_rand.nil? && !aux_rand.is_a?(String)
      private_key = hex2bin(private_key)
      data = hex2bin(data)

      with_context do |context|
        keypair = [create_keypair(private_key)].pack('H*')
        keypair = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
        signature = FFI::MemoryPointer.new(:uchar, 64)
        msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
        aux_rand = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, aux_rand) if aux_rand
        raise Error, 'Failed to generate schnorr signature.' unless secp256k1_schnorrsig_sign32(context, signature, msg32, keypair, aux_rand) == 1
        signature.read_string(64)
      end
    end

    # Magic bytes for secp256k1_schnorrsig_extraparams.
    SCHNORRSIG_EXTRAPARAMS_MAGIC = [0xda, 0x6f, 0xb3, 0x8c].pack('C*').freeze

    # Sign to a variable-length message using schnorr (BIP340 sign with custom parameters).
    # @param [String] data The message being signed with binary format. Unlike {#sign_schnorr}, the length is arbitrary.
    # @param [String] private_key a private key with hex format using sign.
    # @param [String] aux_rand (Optional)The 32-byte extra entropy.
    # @return [String] signature data with binary format(64 bytes).
    # @raise [Secp256k1::Error] If signing failed.
    # @raise [ArgumentError] If invalid arguments specified.
    def sign_schnorr_custom(data, private_key, aux_rand = nil)
      raise ArgumentError, "data must be String." unless data.is_a?(String)
      validate_string!("private_key", private_key, 32)
      validate_string!("aux_rand", aux_rand, 32) if aux_rand
      private_key = hex2bin(private_key)
      data = hex2bin(data)
      aux_rand = hex2bin(aux_rand) if aux_rand

      with_context do |context|
        keypair = [create_keypair(private_key)].pack('H*')
        keypair = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
        signature = FFI::MemoryPointer.new(:uchar, 64)
        msg = FFI::MemoryPointer.new(:uchar, [data.bytesize, 1].max).put_bytes(0, data)

        # Build secp256k1_schnorrsig_extraparams: magic[4], noncefp(NULL=default BIP340), ndata(aux_rand or NULL).
        ptr_size = FFI::Pointer.size
        extraparams = FFI::MemoryPointer.new(:uchar, ptr_size * 3)
        extraparams.put_bytes(0, SCHNORRSIG_EXTRAPARAMS_MAGIC)
        extraparams.put_pointer(ptr_size, FFI::Pointer::NULL)
        ndata = aux_rand ? FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, aux_rand) : FFI::Pointer::NULL
        extraparams.put_pointer(ptr_size * 2, ndata)

        raise Error, 'Failed to generate schnorr signature.' unless secp256k1_schnorrsig_sign_custom(context, signature, msg, data.bytesize, keypair, extraparams) == 1
        signature.read_string(64)
      end
    end

    # Verify schnorr signature.
    # @param [String] data The 32-byte message hash assumed to be signed.
    # @param [String] signature signature data with binary format
    # @param [String] pubkey a public key with hex format using verify.
    # @return [Boolean] verification result.
    # @raise [ArgumentError] If invalid arguments specified.
    def verify_schnorr(data, signature, pubkey)
      validate_string!("data", data, 32)
      verify_schnorr_internal(data, signature, pubkey)
    end

    # Verify a schnorr signature over a variable-length message (counterpart of {#sign_schnorr_custom}).
    # @param [String] data The message assumed to be signed. The length is arbitrary.
    # @param [String] signature signature data with binary format(64 bytes).
    # @param [String] pubkey an x-only public key with hex format(32 bytes) using verify.
    # @return [Boolean] verification result.
    # @raise [ArgumentError] If invalid arguments specified.
    def verify_schnorr_custom(data, signature, pubkey)
      raise ArgumentError, "data must be String." unless data.is_a?(String)
      verify_schnorr_internal(data, signature, pubkey)
    end

    private

    def verify_schnorr_internal(data, signature, pubkey)
      validate_string!("signature", signature, 64)
      validate_string!("pubkey", pubkey, 32)
      data = hex2bin(data)
      pubkey = hex2bin(pubkey)
      signature = hex2bin(signature)
      with_context do |context|
        return false if data.bytesize == 0
        pubkey = [full_pubkey_from_xonly_pubkey(pubkey)].pack('H*')
        xonly_pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
        signature = FFI::MemoryPointer.new(:uchar, signature.bytesize).put_bytes(0, signature)
        msg = FFI::MemoryPointer.new(:uchar, [data.bytesize, 1].max).put_bytes(0, data)
        result = secp256k1_schnorrsig_verify(context, signature, msg, data.bytesize, xonly_pubkey)
        result == 1
      end
    end
  end
end