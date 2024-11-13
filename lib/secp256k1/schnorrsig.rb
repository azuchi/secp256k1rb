module Secp256k1
  module SchnorrSig

    # Sign to data using schnorr.
    # @param [String] data The 32-byte message hash being signed with binary format.
    # @param [String] private_key a private key with hex format using sign.
    # @param [String] aux_rand a extra entropy.
    # @return [String] signature data with binary format. If unsupported algorithm specified, return nil.
    # @raise [ArgumentError] If invalid arguments specified.
    def sign_schnorr(data, private_key, aux_rand = nil)
      raise ArgumentError, "private_key must be String." unless private_key.is_a?(String)
      raise ArgumentError, "data must by String." unless data.is_a?(String)
      raise ArgumentError, "aux_rand must be String." if !aux_rand.nil? && !aux_rand.is_a?(String)
      private_key = hex2bin(private_key)
      raise ArgumentError, "private_key must be 32 bytes." unless private_key.bytesize == 32
      data = hex2bin(data)
      raise ArgumentError, "data must be 32 bytes." unless data.bytesize == 32

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

    # Verify ecdsa signature.
    # @param [String] data The 32-byte message hash assumed to be signed.
    # @param [String] signature signature data with binary format
    # @param [String] pubkey a public key with hex format using verify.
    # @return [Boolean] verification result.
    # @raise [ArgumentError] If invalid arguments specified.
    def verify_schnorr(data, signature, pubkey)
      raise ArgumentError, "sig must be String." unless signature.is_a?(String)
      raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
      raise ArgumentError, "data must be String." unless data.is_a?(String)
      data = hex2bin(data)
      raise ArgumentError, "data must be 32 bytes." unless data.bytesize == 32
      pubkey = hex2bin(pubkey)
      signature = hex2bin(signature)
      with_context do |context|
        return false if data.bytesize == 0
        pubkey = [full_pubkey_from_xonly_pubkey(pubkey)].pack('H*')
        xonly_pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
        signature = FFI::MemoryPointer.new(:uchar, signature.bytesize).put_bytes(0, signature)
        msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
        result = secp256k1_schnorrsig_verify(context, signature, msg32, 32, xonly_pubkey)
        result == 1
      end
    end
  end
end