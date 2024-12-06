# frozen_string_literal: true

require 'securerandom'
require_relative "secp256k1/version"
require_relative 'secp256k1/c'
require_relative 'secp256k1/recovery'
require_relative 'secp256k1/ellswift'
require_relative 'secp256k1/schnorrsig'
require_relative 'secp256k1/musig'

# Binding for secp256k1 (https://github.com/bitcoin-core/secp256k1/)
module Secp256k1

  class Error < StandardError; end

  include C
  include Recover
  include SchnorrSig
  include EllSwift
  include MuSig

  FLAGS_TYPE_MASK = ((1 << 8) - 1)
  FLAGS_TYPE_CONTEXT = (1 << 0)
  FLAGS_TYPE_COMPRESSION = (1 << 1)

  FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
  FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
  FLAGS_BIT_COMPRESSION = (1 << 8)

  # Flags to pass to context_create.
  CONTEXT_VERIFY = (FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_VERIFY)
  CONTEXT_SIGN = (FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_SIGN)

  # Flag to pass to ec_pubkey_serialize and ec_privkey_export.
  EC_COMPRESSED = (FLAGS_TYPE_COMPRESSION | FLAGS_BIT_COMPRESSION)
  EC_UNCOMPRESSED = (FLAGS_TYPE_COMPRESSION)

  X_ONLY_PUBKEY_SIZE = 32
  ELL_SWIFT_KEY_SIZE = 64

  # Creates a secp256k1 context object, performs the operations passed in the block,
  # and then ensures that the secp256k1 context object is destroyed at the end.
  # @param [Integer] flags The flag to use when performing the operation.
  # @raise [Secp256k1::Error] If secp256k1_context_randomize failed.
  def with_context(flags: (CONTEXT_VERIFY | CONTEXT_SIGN))
    begin
      context = secp256k1_context_create(flags)
      ret, tries, max = 0, 0, 20
      while ret != 1
        raise Error, 'secp256k1_context_randomize failed.' if tries >= max
        tries += 1
        ret = secp256k1_context_randomize(context, FFI::MemoryPointer.from_string(SecureRandom.random_bytes(32)))
      end
      yield(context) if block_given?
    ensure
      secp256k1_context_destroy(context)
    end
  end

  # Randomly generate ec private key and public key.
  # @param [Boolean] compressed Whether to generate a compressed public key.
  # @return [Array] Array of public key and public key (Both are hex values).
  # @raise [Secp256k1::Error] If secp256k1_ec_seckey_verify in generate_key_pair failed.
  def generate_key_pair(compressed: true)
    with_context do |context|
      ret, tries, max = 0, 0, 20
      while ret != 1
        raise Error, 'secp256k1_ec_seckey_verify in generate_key_pair failed.' if tries >= max
        tries += 1
        private_key = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.random_bytes(32))
        ret = secp256k1_ec_seckey_verify(context, private_key)
      end
      private_key =  private_key.read_string(32).unpack1('H*')
      [private_key , generate_pubkey_in_context(context,  private_key, compressed: compressed) ]
    end
  end

  # Generate public key from +private_key+.
  # @param [String] private_key Private key with hex format.
  # @param [Boolean] compressed Whether to generate a compressed public key.
  # @return [String] Public key with hex format.
  # @raise [ArgumentError] If invalid arguments specified.
  def generate_pubkey(private_key, compressed: true)
    validate_string!("private_key", private_key, 32)
    private_key = hex2bin(private_key)
    with_context do |context|
      generate_pubkey_in_context(context, private_key, compressed: compressed)
    end
  end

  # Validate whether this is a valid public key.
  # @param [String] pubkey public key with hex format.
  # @param [Boolean] allow_hybrid whether support hybrid public key.
  # @return [Boolean] If valid public key return true, otherwise false.
  # @raise [ArgumentError] If invalid arguments specified.
  def parse_ec_pubkey?(pubkey, allow_hybrid = false)
    raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
    pubkey = hex2bin(pubkey)
    return false if !allow_hybrid && ![0x02, 0x03, 0x04].include?(pubkey[0].ord)
    with_context do |context|
      pubkey_size = pubkey.bytesize
      pubkey = FFI::MemoryPointer.new(:uchar, pubkey_size).put_bytes(0, pubkey)
      internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
      result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pubkey_size)
      result == 1
    end
  end

  # Create key pair data from private key.
  # @param [String] private_key with hex format
  # @return [String] key pair data with hex format. data = private key(32 bytes) | public key(64 bytes).
  # @raise [Secp256k1::Error] If private_key is invalid.
  # @raise [ArgumentError] If invalid arguments specified.
  def create_keypair(private_key)
    validate_string!("private_key", private_key, 32)
    private_key = hex2bin(private_key)
    with_context do |context|
      secret = FFI::MemoryPointer.new(:uchar, private_key.bytesize).put_bytes(0, private_key)
      raise Error, 'private_key is invalid.' unless secp256k1_ec_seckey_verify(context, secret)
      keypair = FFI::MemoryPointer.new(:uchar, 96)
      raise Error 'private_key is invalid.' unless secp256k1_keypair_create(context, keypair, secret) == 1
      keypair.read_string(96).unpack1('H*')
    end
  end

  # Check whether valid x-only public key or not.
  # @param [String] pubkey x-only public key with hex format(32 bytes).
  # @return [Boolean] result.
  def valid_xonly_pubkey?(pubkey)
    return false unless pubkey.is_a?(String)
    begin
      full_pubkey_from_xonly_pubkey(hex2bin(pubkey))
    rescue Exception
      return false
    end
    true
  end

  # Sign to data using ecdsa.
  # @param [String] data The 32-byte message hash being signed with binary format.
  # @param [String] private_key a private key with hex format using sign.
  # @param [String] extra_entropy An extra entropy with binary format for rfc6979.
  # @return [String] signature data with binary format. If unsupported algorithm specified, return nil.
  # @raise [ArgumentError] If invalid arguments specified.
  def sign_ecdsa(data, private_key, extra_entropy = nil)
    validate_string!("private_key", private_key, 32)
    validate_string!("data", data, 32)
    validate_string!("extra_entropy", extra_entropy, 32) if extra_entropy
    private_key = hex2bin(private_key)
    data = hex2bin(data)

    with_context do |context|
      secret = FFI::MemoryPointer.new(:uchar, private_key.bytesize).put_bytes(0, private_key)
      raise Error, 'private_key is invalid' unless secp256k1_ec_seckey_verify(context, secret)

      internal_signature = FFI::MemoryPointer.new(:uchar, 64)
      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
      entropy = extra_entropy ? FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, extra_entropy) : nil

      ret, tries, max = 0, 0, 20

      while ret != 1
        raise Error, 'secp256k1_ecdsa_sign failed.' if tries >= max
        tries += 1
        ret = secp256k1_ecdsa_sign(context, internal_signature, msg32, secret, nil, entropy)
      end

      signature = FFI::MemoryPointer.new(:uchar, 72)
      signature_len = FFI::MemoryPointer.new(:uint64).put_uint64(0, 72)
      result = secp256k1_ecdsa_signature_serialize_der(context, signature, signature_len, internal_signature)
      raise Error, 'secp256k1_ecdsa_signature_serialize_der failed' unless result

      signature.read_string(signature_len.read_uint64)
    end
  end

  # Verify ecdsa signature.
  # @param [String] data The 32-byte message hash assumed to be signed.
  # @param [String] signature signature data with binary format
  # @param [String] pubkey a public key with hex format using verify.
  # @return [Boolean] verification result.
  # @raise [ArgumentError] If invalid arguments specified.
  def verify_ecdsa(data, signature, pubkey)
    raise ArgumentError, "sig must be String." unless signature.is_a?(String)
    raise ArgumentError, "pubkey must be String." unless pubkey.is_a?(String)
    validate_string!("data", data, 32)
    data = hex2bin(data)
    pubkey = hex2bin(pubkey)
    signature = hex2bin(signature)
    with_context do |context|
      return false if data.bytesize == 0
      pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
      internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
      result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pubkey.size)
      return false unless result

      signature = FFI::MemoryPointer.new(:uchar, signature.bytesize).put_bytes(0, signature)
      internal_signature = FFI::MemoryPointer.new(:uchar, 64)
      result = secp256k1_ecdsa_signature_parse_der(context, internal_signature, signature, signature.size)
      return false unless result

      # libsecp256k1's ECDSA verification requires lower-S signatures, which have not historically been enforced in Bitcoin, so normalize them first.
      secp256k1_ecdsa_signature_normalize(context, internal_signature, internal_signature)

      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
      result = secp256k1_ecdsa_verify(context, internal_signature, msg32, internal_pubkey)

      result == 1
    end
  end

  private

  # Calculate full public key(64 bytes) from public key(32 bytes).
  # @param [String] pubkey x-only public key with hex format(32 bytes).
  # @return [String] x-only public key with hex format(64 bytes).
  # @raise ArgumentError
  def full_pubkey_from_xonly_pubkey(pubkey)
    with_context do |context|
      raise ArgumentError, "Pubkey size must be #{X_ONLY_PUBKEY_SIZE} bytes." unless pubkey.bytesize == X_ONLY_PUBKEY_SIZE
      xonly_pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
      full_pubkey = FFI::MemoryPointer.new(:uchar, 64)
      raise ArgumentError, 'An invalid public key was specified.' unless secp256k1_xonly_pubkey_parse(context, full_pubkey, xonly_pubkey) == 1
      full_pubkey.read_string(64).unpack1('H*')
    end
  end

  def generate_pubkey_in_context(context, private_key, compressed: true)
    internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
    priv_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hex2bin(private_key))
    result = secp256k1_ec_pubkey_create(context, internal_pubkey, priv_ptr)
    raise 'error creating pubkey' unless result
    serialize_pubkey_internal(context, internal_pubkey, compressed)
  end

  # Serialize public key.
  def serialize_pubkey_internal(context, pubkey_input, compressed)
    pubkey = FFI::MemoryPointer.new(:uchar, 65)
    pubkey_len = FFI::MemoryPointer.new(:uint64)
    result = if compressed
               pubkey_len.put_uint64(0, 33)
               secp256k1_ec_pubkey_serialize(context, pubkey, pubkey_len, pubkey_input, EC_COMPRESSED)
             else
               pubkey_len.put_uint64(0, 65)
               secp256k1_ec_pubkey_serialize(context, pubkey, pubkey_len, pubkey_input, EC_UNCOMPRESSED)
             end
    raise Error, 'error serialize pubkey' unless result || pubkey_len.read_uint64 > 0
    pubkey.read_string(pubkey_len.read_uint64).unpack1('H*')
  end

  def hex_string?(str)
    return false if str.bytes.any? { |b| b > 127 }
    return false if str.length % 2 != 0
    hex_chars = str.chars.to_a
    hex_chars.all? { |c| c =~ /[0-9a-fA-F]/ }
  end

  def hex2bin(str)
    hex_string?(str) ? [str].pack('H*') : str
  end

  def validate_string!(name, target, byte_length)
    raise ArgumentError, "#{name} must be String." unless target.is_a?(String)
    raise ArgumentError, "#{name} must be #{byte_length} bytes." unless hex2bin(target).bytesize == byte_length
  end
end

