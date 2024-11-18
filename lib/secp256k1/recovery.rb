module Secp256k1
  module Recover
    # Sign data with compact format.
    # @param [String] data The 32-byte message hash being signed.
    # @param [String] private_key a private key using sign with hex format
    # @return [Array] Array of signature and recovery id.
    # @raise [Secp256k1::Error] If recovery failed.
    # @raise [ArgumentError] If invalid arguments specified.
    def sign_recoverable(data, private_key)
      validate_string!("private_key", private_key, 32)
      validate_string!("data", data, 32)
      private_key = hex2bin(private_key)
      data = hex2bin(data)
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
    # @param [String] signature The signature with binary format (65 bytes).
    # @param [Boolean] compressed whether compressed public key or not.
    # @return [String] Recovered public key with hex format.
    # @raise [Secp256k1::Error] If recover failed.
    # @raise [ArgumentError] If invalid arguments specified.
    def recover(data, signature, compressed)
      validate_string!("data", data, 32)
      validate_string!("signature", signature, 65)
      signature = hex2bin(signature)
      data = hex2bin(data)
      rec = (signature[0].ord - 0x1b) & 3
      raise ArgumentError, "rec must be between 0 and 3." if rec < 0 || rec > 3

      with_context do |context|
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