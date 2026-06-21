module Secp256k1
  # Key module provides EC key arithmetic (tweak/negate/combine), x-only public key
  # operations used by Taproot, and key pair accessors.
  # @example
  #   include Secp256k1
  #
  #   sk, pk = generate_key_pair
  #   tweak = SecureRandom.bytes(32)
  #
  #   # Tweak a private/public key.
  #   tweaked_sk = tweak_add_seckey(sk, tweak)
  #   tweaked_pk = tweak_add_pubkey(pk, tweak)
  #
  module Key

    # Negate a private key in place and return the result.
    # @param [String] private_key a private key with hex format.
    # @return [String] negated private key with hex format.
    # @raise [Secp256k1::Error] If the private key is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def negate_seckey(private_key)
      validate_string!("private_key", private_key, 32)
      private_key = hex2bin(private_key)
      with_context do |context|
        seckey = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, private_key)
        raise Error, 'secp256k1_ec_seckey_negate failed.' unless secp256k1_ec_seckey_negate(context, seckey) == 1
        seckey.read_string(32).unpack1('H*')
      end
    end

    # Tweak a private key by adding +tweak+ to it.
    # @param [String] private_key a private key with hex format.
    # @param [String] tweak a 32-byte tweak with hex format.
    # @return [String] tweaked private key with hex format.
    # @raise [Secp256k1::Error] If the arguments are invalid or the result is the zero key.
    # @raise [ArgumentError] If invalid arguments specified.
    def tweak_add_seckey(private_key, tweak)
      tweak_seckey(private_key, tweak, :secp256k1_ec_seckey_tweak_add)
    end

    # Tweak a private key by multiplying it by +tweak+.
    # @param [String] private_key a private key with hex format.
    # @param [String] tweak a 32-byte tweak with hex format.
    # @return [String] tweaked private key with hex format.
    # @raise [Secp256k1::Error] If the arguments are invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def tweak_mul_seckey(private_key, tweak)
      tweak_seckey(private_key, tweak, :secp256k1_ec_seckey_tweak_mul)
    end

    # Negate a public key.
    # @param [String] pubkey a public key with hex format.
    # @param [Boolean] compressed Whether to return a compressed public key.
    # @return [String] negated public key with hex format.
    # @raise [Secp256k1::Error] If the public key is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def negate_pubkey(pubkey, compressed: true)
      raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
      pubkey = hex2bin(pubkey)
      with_context do |context|
        internal = parse_pubkey_internal(context, pubkey)
        raise Error, 'secp256k1_ec_pubkey_negate failed.' unless secp256k1_ec_pubkey_negate(context, internal) == 1
        serialize_pubkey_internal(context, internal, compressed)
      end
    end

    # Tweak a public key by adding +tweak+ * G to it.
    # @param [String] pubkey a public key with hex format.
    # @param [String] tweak a 32-byte tweak with hex format.
    # @param [Boolean] compressed Whether to return a compressed public key.
    # @return [String] tweaked public key with hex format.
    # @raise [Secp256k1::Error] If the arguments are invalid or the result is the point at infinity.
    # @raise [ArgumentError] If invalid arguments specified.
    def tweak_add_pubkey(pubkey, tweak, compressed: true)
      tweak_pubkey(pubkey, tweak, :secp256k1_ec_pubkey_tweak_add, compressed: compressed)
    end

    # Tweak a public key by multiplying it by +tweak+.
    # @param [String] pubkey a public key with hex format.
    # @param [String] tweak a 32-byte tweak with hex format.
    # @param [Boolean] compressed Whether to return a compressed public key.
    # @return [String] tweaked public key with hex format.
    # @raise [Secp256k1::Error] If the arguments are invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def tweak_mul_pubkey(pubkey, tweak, compressed: true)
      tweak_pubkey(pubkey, tweak, :secp256k1_ec_pubkey_tweak_mul, compressed: compressed)
    end

    # Add a number of public keys together.
    # @param [Array<String>] pubkeys an array of public keys with hex format.
    # @param [Boolean] compressed Whether to return a compressed public key.
    # @return [String] the sum of the public keys with hex format.
    # @raise [Secp256k1::Error] If the sum is the point at infinity.
    # @raise [ArgumentError] If invalid arguments specified.
    def combine_pubkeys(pubkeys, compressed: true)
      raise ArgumentError, "pubkeys must be Array." unless pubkeys.is_a?(Array)
      raise ArgumentError, "pubkeys must not be empty." if pubkeys.empty?
      with_context do |context|
        internals = pubkeys.map do |pubkey|
          raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
          parse_pubkey_internal(context, hex2bin(pubkey))
        end
        ins = FFI::MemoryPointer.new(:pointer, internals.size)
        ins.write_array_of_pointer(internals)
        combined = FFI::MemoryPointer.new(:uchar, 64)
        raise Error, 'secp256k1_ec_pubkey_combine failed.' unless secp256k1_ec_pubkey_combine(context, combined, ins, internals.size) == 1
        serialize_pubkey_internal(context, combined, compressed)
      end
    end

    # Convert a public key into an x-only public key.
    # @param [String] pubkey a public key with hex format.
    # @return [Array(String, Integer)] the x-only public key with hex format(32 bytes) and its parity(0 or 1).
    # @raise [Secp256k1::Error] If the public key is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def xonly_pubkey_from_pubkey(pubkey)
      raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
      pubkey = hex2bin(pubkey)
      with_context do |context|
        internal = parse_pubkey_internal(context, pubkey)
        xonly = FFI::MemoryPointer.new(:uchar, 64)
        parity = FFI::MemoryPointer.new(:int)
        raise Error, 'secp256k1_xonly_pubkey_from_pubkey failed.' unless secp256k1_xonly_pubkey_from_pubkey(context, xonly, parity, internal) == 1
        [serialize_xonly_pubkey_internal(context, xonly), parity.read_int]
      end
    end

    # Tweak an x-only public key by adding +tweak+ * G to it (used for Taproot output key derivation).
    # @param [String] xonly_pubkey an x-only public key with hex format(32 bytes).
    # @param [String] tweak a 32-byte tweak with hex format.
    # @param [Boolean] compressed Whether to return a compressed public key.
    # @return [Array(String, Integer)] the tweaked(full) public key with hex format and the parity(0 or 1) of the tweaked key.
    # @raise [Secp256k1::Error] If the arguments are invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def xonly_tweak_add_pubkey(xonly_pubkey, tweak, compressed: true)
      validate_string!("xonly_pubkey", xonly_pubkey, X_ONLY_PUBKEY_SIZE)
      validate_string!("tweak", tweak, 32)
      xonly_pubkey = hex2bin(xonly_pubkey)
      tweak = hex2bin(tweak)
      with_context do |context|
        xonly = FFI::MemoryPointer.new(:uchar, X_ONLY_PUBKEY_SIZE).put_bytes(0, xonly_pubkey)
        internal = FFI::MemoryPointer.new(:uchar, 64)
        raise Error, 'An invalid x-only public key was specified.' unless secp256k1_xonly_pubkey_parse(context, internal, xonly) == 1
        tweak_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, tweak)
        output = FFI::MemoryPointer.new(:uchar, 64)
        raise Error, 'secp256k1_xonly_pubkey_tweak_add failed.' unless secp256k1_xonly_pubkey_tweak_add(context, output, internal, tweak_ptr) == 1
        _, parity = xonly_pubkey_from_internal(context, output)
        [serialize_pubkey_internal(context, output, compressed), parity]
      end
    end

    # Check that a tweaked x-only public key was computed by tweaking +internal_pubkey+ with +tweak+.
    # @param [String] tweaked_pubkey32 the tweaked x-only public key with hex format(32 bytes).
    # @param [Integer] tweaked_pk_parity the parity(0 or 1) of the tweaked public key.
    # @param [String] internal_pubkey the internal x-only public key with hex format(32 bytes).
    # @param [String] tweak a 32-byte tweak with hex format.
    # @return [Boolean] verification result.
    # @raise [ArgumentError] If invalid arguments specified.
    def xonly_tweak_add_check?(tweaked_pubkey32, tweaked_pk_parity, internal_pubkey, tweak)
      validate_string!("tweaked_pubkey32", tweaked_pubkey32, X_ONLY_PUBKEY_SIZE)
      validate_string!("internal_pubkey", internal_pubkey, X_ONLY_PUBKEY_SIZE)
      validate_string!("tweak", tweak, 32)
      raise ArgumentError, "tweaked_pk_parity must be 0 or 1." unless [0, 1].include?(tweaked_pk_parity)
      tweaked_pubkey32 = hex2bin(tweaked_pubkey32)
      internal_pubkey = hex2bin(internal_pubkey)
      tweak = hex2bin(tweak)
      with_context do |context|
        internal = FFI::MemoryPointer.new(:uchar, X_ONLY_PUBKEY_SIZE).put_bytes(0, internal_pubkey)
        internal_xonly = FFI::MemoryPointer.new(:uchar, 64)
        return false unless secp256k1_xonly_pubkey_parse(context, internal_xonly, internal) == 1
        tweaked_ptr = FFI::MemoryPointer.new(:uchar, X_ONLY_PUBKEY_SIZE).put_bytes(0, tweaked_pubkey32)
        tweak_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, tweak)
        secp256k1_xonly_pubkey_tweak_add_check(context, tweaked_ptr, tweaked_pk_parity, internal_xonly, tweak_ptr) == 1
      end
    end

    # Get the public key from a key pair.
    # @param [String] keypair a key pair with hex format(96 bytes), created by {#create_keypair}.
    # @param [Boolean] compressed Whether to return a compressed public key.
    # @return [String] public key with hex format.
    # @raise [Secp256k1::Error] If the key pair is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def keypair_to_pubkey(keypair, compressed: true)
      validate_string!("keypair", keypair, 96)
      keypair = hex2bin(keypair)
      with_context do |context|
        keypair_ptr = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
        internal = FFI::MemoryPointer.new(:uchar, 64)
        raise Error, 'secp256k1_keypair_pub failed.' unless secp256k1_keypair_pub(context, internal, keypair_ptr) == 1
        serialize_pubkey_internal(context, internal, compressed)
      end
    end

    # Get the private key from a key pair.
    # @param [String] keypair a key pair with hex format(96 bytes), created by {#create_keypair}.
    # @return [String] private key with hex format.
    # @raise [Secp256k1::Error] If the key pair is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def keypair_to_seckey(keypair)
      validate_string!("keypair", keypair, 96)
      keypair = hex2bin(keypair)
      with_context do |context|
        keypair_ptr = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
        seckey = FFI::MemoryPointer.new(:uchar, 32)
        raise Error, 'secp256k1_keypair_sec failed.' unless secp256k1_keypair_sec(context, seckey, keypair_ptr) == 1
        seckey.read_string(32).unpack1('H*')
      end
    end

    # Get the x-only public key from a key pair.
    # @param [String] keypair a key pair with hex format(96 bytes), created by {#create_keypair}.
    # @return [Array(String, Integer)] the x-only public key with hex format(32 bytes) and its parity(0 or 1).
    # @raise [Secp256k1::Error] If the key pair is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def keypair_to_xonly_pubkey(keypair)
      validate_string!("keypair", keypair, 96)
      keypair = hex2bin(keypair)
      with_context do |context|
        keypair_ptr = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
        xonly = FFI::MemoryPointer.new(:uchar, 64)
        parity = FFI::MemoryPointer.new(:int)
        raise Error, 'secp256k1_keypair_xonly_pub failed.' unless secp256k1_keypair_xonly_pub(context, xonly, parity, keypair_ptr) == 1
        [serialize_xonly_pubkey_internal(context, xonly), parity.read_int]
      end
    end

    # Compare two public keys using lexicographic(of compressed serialization) order.
    # @param [String] pubkey1 a public key with hex format.
    # @param [String] pubkey2 a public key with hex format.
    # @return [Integer] negative if pubkey1 < pubkey2, 0 if equal, positive if pubkey1 > pubkey2.
    # @raise [Secp256k1::Error] If a public key is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def compare_pubkey(pubkey1, pubkey2)
      raise ArgumentError, "pubkey1 must be String." unless pubkey1.is_a?(String)
      raise ArgumentError, "pubkey2 must be String." unless pubkey2.is_a?(String)
      with_context do |context|
        a = parse_pubkey_internal(context, hex2bin(pubkey1))
        b = parse_pubkey_internal(context, hex2bin(pubkey2))
        secp256k1_ec_pubkey_cmp(context, a, b)
      end
    end

    # Sort public keys using lexicographic(of compressed serialization) order.
    # @param [Array<String>] pubkeys an array of public keys with hex format.
    # @param [Boolean] compressed Whether to return compressed public keys.
    # @return [Array<String>] the sorted public keys with hex format.
    # @raise [Secp256k1::Error] If a public key is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def sort_pubkeys(pubkeys, compressed: true)
      raise ArgumentError, "pubkeys must be Array." unless pubkeys.is_a?(Array)
      raise ArgumentError, "pubkeys must not be empty." if pubkeys.empty?
      with_context do |context|
        internals = pubkeys.map do |pubkey|
          raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
          parse_pubkey_internal(context, hex2bin(pubkey))
        end
        arr = FFI::MemoryPointer.new(:pointer, internals.size)
        arr.write_array_of_pointer(internals)
        raise Error, 'secp256k1_ec_pubkey_sort failed.' unless secp256k1_ec_pubkey_sort(context, arr, internals.size) == 1
        arr.read_array_of_pointer(internals.size).map { |ptr| serialize_pubkey_internal(context, ptr, compressed) }
      end
    end

    # Compare two x-only public keys using lexicographic order.
    # @param [String] pubkey1 an x-only public key with hex format(32 bytes).
    # @param [String] pubkey2 an x-only public key with hex format(32 bytes).
    # @return [Integer] negative if pubkey1 < pubkey2, 0 if equal, positive if pubkey1 > pubkey2.
    # @raise [Secp256k1::Error] If a public key is invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def compare_xonly_pubkey(pubkey1, pubkey2)
      validate_string!("pubkey1", pubkey1, X_ONLY_PUBKEY_SIZE)
      validate_string!("pubkey2", pubkey2, X_ONLY_PUBKEY_SIZE)
      with_context do |context|
        a = parse_xonly_pubkey_internal(context, hex2bin(pubkey1))
        b = parse_xonly_pubkey_internal(context, hex2bin(pubkey2))
        secp256k1_xonly_pubkey_cmp(context, a, b)
      end
    end

    # Tweak a key pair by adding +tweak+ to the key pair's x-only context.
    # @param [String] keypair a key pair with hex format(96 bytes), created by {#create_keypair}.
    # @param [String] tweak a 32-byte tweak with hex format.
    # @return [String] the tweaked key pair with hex format(96 bytes).
    # @raise [Secp256k1::Error] If the arguments are invalid.
    # @raise [ArgumentError] If invalid arguments specified.
    def keypair_xonly_tweak_add(keypair, tweak)
      validate_string!("keypair", keypair, 96)
      validate_string!("tweak", tweak, 32)
      keypair = hex2bin(keypair)
      tweak = hex2bin(tweak)
      with_context do |context|
        keypair_ptr = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
        tweak_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, tweak)
        raise Error, 'secp256k1_keypair_xonly_tweak_add failed.' unless secp256k1_keypair_xonly_tweak_add(context, keypair_ptr, tweak_ptr) == 1
        keypair_ptr.read_string(96).unpack1('H*')
      end
    end

    private

    def parse_xonly_pubkey_internal(context, xonly_pubkey)
      xonly = FFI::MemoryPointer.new(:uchar, X_ONLY_PUBKEY_SIZE).put_bytes(0, xonly_pubkey)
      internal = FFI::MemoryPointer.new(:uchar, 64)
      raise Error, 'An invalid x-only public key was specified.' unless secp256k1_xonly_pubkey_parse(context, internal, xonly) == 1
      internal
    end

    def tweak_seckey(private_key, tweak, func)
      validate_string!("private_key", private_key, 32)
      validate_string!("tweak", tweak, 32)
      private_key = hex2bin(private_key)
      tweak = hex2bin(tweak)
      with_context do |context|
        seckey = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, private_key)
        tweak_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, tweak)
        raise Error, "#{func} failed." unless send(func, context, seckey, tweak_ptr) == 1
        seckey.read_string(32).unpack1('H*')
      end
    end

    def tweak_pubkey(pubkey, tweak, func, compressed: true)
      raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
      validate_string!("tweak", tweak, 32)
      pubkey = hex2bin(pubkey)
      tweak = hex2bin(tweak)
      with_context do |context|
        internal = parse_pubkey_internal(context, pubkey)
        tweak_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, tweak)
        raise Error, "#{func} failed." unless send(func, context, internal, tweak_ptr) == 1
        serialize_pubkey_internal(context, internal, compressed)
      end
    end

    # Get x-only pubkey and parity from an internal(64 bytes) full pubkey pointer.
    def xonly_pubkey_from_internal(context, internal_pubkey)
      xonly = FFI::MemoryPointer.new(:uchar, 64)
      parity = FFI::MemoryPointer.new(:int)
      raise Error, 'secp256k1_xonly_pubkey_from_pubkey failed.' unless secp256k1_xonly_pubkey_from_pubkey(context, xonly, parity, internal_pubkey) == 1
      [serialize_xonly_pubkey_internal(context, xonly), parity.read_int]
    end
  end
end
