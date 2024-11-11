module Secp256k1
  module Recover
    # Sign data with compact format.
    # @param [String] data The 32-byte message hash being signed.
    # @param [String] private_key a private key using sign with hex format
    # @return [Array] Array of signature and recovery id.
    # @raise [Secp256k1::Error] If recovery failed.
    # @raise [ArgumentError] If invalid arguments specified.
    def sign_recoverable(data, private_key)
      raise ArgumentError, "private_key must be String." unless private_key.is_a?(String)
      raise ArgumentError, "data must by String." unless data.is_a?(String)
      private_key = hex2bin(private_key)
      raise ArgumentError, "private_key must be 32 bytes." unless private_key.bytesize == 32
      data = hex2bin(data)
      raise ArgumentError, "data must be 32 bytes." unless data.bytesize == 32

      with_context do |context|
        sig = FFI::MemoryPointer.new(:uchar, 65)
        hash =FFI::MemoryPointer.new(:uchar, data.bytesize).put_bytes(0, data)
        sec_key = FFI::MemoryPointer.new(:uchar, private_key.bytesize).put_bytes(0, private_key)
        result = secp256k1_ecdsa_sign_recoverable(context, sig, hash, sec_key, nil, nil)
        raise Error, 'secp256k1_ecdsa_sign_recoverable failed.' if result == 0

        output = FFI::MemoryPointer.new(:uchar, 64)
        rec = FFI::MemoryPointer.new(:uint64)
        result = secp256k1_ecdsa_recoverable_signature_serialize_compact(context, output, rec, sig)
        raise Error, 'secp256k1_ecdsa_recoverable_signature_serialize_compact failed.' unless result == 1

        sig = output.read_string(64).unpack1('H*')
        [sig, rec.read(:int)]
      end
    end

    # Recover public key from compact signature.
    # @param [String] data The 32-byte message hash assumed to be signed.
    # @param [String] signature The signature with binary format.
    # @param [Boolean] compressed whether compressed public key or not.
    # @return [String] Recovered public key with hex format.
    # @raise [Secp256k1::Error] If recover failed.
    # @raise [ArgumentError] If invalid arguments specified.
    def recover(data, signature, compressed)
      raise ArgumentError, "data must be String." unless data.is_a?(String)
      raise ArgumentError, "signature must be String." unless signature.is_a?(String)
      signature = hex2bin(signature)
      raise ArgumentError, "signature must be 65 bytes." unless signature.bytesize == 65
      data = hex2bin(data)
      raise ArgumentError, "data must be 32 bytes." unless data.bytesize == 32

      with_context do |context|
        rec = (signature.unpack1('C') - 27) & 3
        sig = FFI::MemoryPointer.new(:uchar, 65)
        input = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, signature[1..-1])
        result = secp256k1_ecdsa_recoverable_signature_parse_compact(context, sig, input, rec)
        raise Error, 'secp256k1_ecdsa_recoverable_signature_parse_compact failed.' unless result == 1

        pubkey = FFI::MemoryPointer.new(:uchar, 64)
        msg = FFI::MemoryPointer.new(:uchar, data.bytesize).put_bytes(0, data)
        result = secp256k1_ecdsa_recover(context, pubkey, sig, msg)
        raise Error, 'secp256k1_ecdsa_recover failed.' unless result == 1

        serialize_pubkey_internal(context, pubkey.read_string(64), compressed)
      end
    end
  end
end