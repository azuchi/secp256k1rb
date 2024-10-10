# frozen_string_literal: true

require 'securerandom'
require_relative "secp256k1/version"
require_relative 'secp256k1/c'

# Binding for secp256k1 (https://github.com/bitcoin-core/secp256k1/)
module Secp256k1

  class Error < StandardError; end

  include C

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
        priv_key = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.random_bytes(32))
        ret = secp256k1_ec_seckey_verify(context, priv_key)
      end
      private_key =  priv_key.read_string(32).unpack1('H*')
      [private_key , generate_pubkey_in_context(context,  private_key, compressed: compressed) ]
    end
  end

  # Generate public key from +priv_key+.
  # @param [String] priv_key
  # @param [Boolean] compressed Whether to generate a compressed public key.
  # @return [String] Public key with hex format.
  def generate_pubkey(priv_key, compressed: true)
    with_context do |context|
      generate_pubkey_in_context(context, priv_key, compressed: compressed)
    end
  end

  # Sign to data.
  # @param [String] data a data to be signed with binary format.
  # @param [String] privkey a private key with hex format using sign.
  # @param [String] extra_entropy a extra entropy with binary format for rfc6979.
  # @param [Symbol] algo signature algorithm. ecdsa(default) or schnorr.
  # @return [String] signature data with binary format. If unsupported algorithm specified, return nil.
  def sign_data(data, privkey, extra_entropy = nil, algo: :ecdsa)
    case algo
    when :ecdsa
      sign_ecdsa(data, privkey, extra_entropy)
    when :schnorr
      sign_schnorr(data, privkey, extra_entropy)
    else
      nil
    end
  end

  # Sign data with compact format.
  # @param [String] data a data to be signed with binary format
  # @param [String] privkey a private key using sign with hex format
  # @return [Array] Array of ECDSA::Signature and recovery id.
  # @raise [Secp256k1::Error] If recovery failed.
  def sign_recoverable(data, privkey)
    with_context do |context|
      sig = FFI::MemoryPointer.new(:uchar, 65)
      hash =FFI::MemoryPointer.new(:uchar, data.bytesize).put_bytes(0, data)
      priv_key = [privkey].pack('H*')
      sec_key = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
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
  # @param [String] data message digest using signature.
  # @param [String] signature signature with binary format.
  # @param [Integer] rec recovery id.
  # @param [Boolean] compressed whether compressed public key or not.
  # @return [String] Recovered public key with hex format.
  # @raise [Secp256k1::Error] If recover failed.
  def recover(data, signature, rec, compressed)
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

  # Verify signature.
  # @param [String] data a data with binary format.
  # @param [String] sig signature data with binary format
  # @param [String] pubkey a public key with hex format using verify.
  # @param [Symbol] algo signature algorithm. ecdsa(default) or schnorr.
  # @return [Boolean] verification result.
  def verify_sig(data, sig, pubkey, algo: :ecdsa)
    case algo
    when :ecdsa
      verify_ecdsa(data, sig, pubkey)
    when :schnorr
      verify_schnorr(data, sig, pubkey)
    else
      false
    end
  end

  # Validate whether this is a valid public key.
  # @param [String] pub_key public key with hex format.
  # @param [Boolean] allow_hybrid whether support hybrid public key.
  # @return [Boolean] If valid public key return true, otherwise false.
  def parse_ec_pubkey?(pub_key, allow_hybrid = false)
    pub_key = [pub_key].pack("H*")
    return false if !allow_hybrid && ![0x02, 0x03, 0x04].include?(pub_key[0].ord)
    with_context do |context|
      pubkey = FFI::MemoryPointer.new(:uchar, pub_key.bytesize).put_bytes(0, pub_key)
      internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
      result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pub_key.bytesize)
      result == 1
    end
  end

  # Create key pair data from private key.
  # @param [String] priv_key with hex format
  # @return [String] key pair data with hex format. data = private key(32 bytes) | public key(64 bytes).
  # @raise [Secp256k1::Error] If priv_key is invalid.
  def create_keypair(priv_key)
    with_context do |context|
      priv_key = [priv_key].pack('H*')
      secret = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
      raise Error, 'priv_key is invalid.' unless secp256k1_ec_seckey_verify(context, secret)
      keypair = FFI::MemoryPointer.new(:uchar, 96)
      raise Error 'priv_key is invalid.' unless secp256k1_keypair_create(context, keypair, secret) == 1
      keypair.read_string(96).unpack1('H*')
    end
  end

  # Check whether valid x-only public key or not.
  # @param [String] pub_key x-only public key with hex format(32 bytes).
  # @return [Boolean] result.
  def valid_xonly_pubkey?(pub_key)
    begin
      full_pubkey_from_xonly_pubkey(pub_key)
    rescue Exception
      return false
    end
    true
  end

  # Decode ellswift public key.
  # @param [String] ell_key ElligatorSwift key with binary format.
  # @return [String] Decoded public key with hex format.
  # @raise [Secp256k1::Error] If decode failed.
  def ellswift_decode(ell_key)
    with_context do |context|
      ell64 = FFI::MemoryPointer.new(:uchar, ell_key.bytesize).put_bytes(0, ell_key)
      internal = FFI::MemoryPointer.new(:uchar, 64)
      result = secp256k1_ellswift_decode(context, internal, ell64)
      raise Error, 'Decode failed.' unless result == 1
      serialize_pubkey_internal(context, internal, true)
    end
  end

  # Compute an ElligatorSwift public key for a secret key.
  # @param [String] priv_key private key with hex format
  # @return [String] ElligatorSwift public key with hex format.
  # @raise [Secp256k1::Error] If failed to create elligattor swhift public key.
  def ellswift_create(priv_key)
    with_context(flags: SECP256K1_CONTEXT_SIGN) do |context|
      ell64 = FFI::MemoryPointer.new(:uchar, 64)
      seckey32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [priv_key].pack('H*'))
      result = secp256k1_ellswift_create(context, ell64, seckey32, nil)
      raise Error, 'Failed to create ElligatorSwift public key.' unless result == 1
      ell64.read_string(64).unpack1('H*')
    end
  end

  # Compute X coordinate of shared ECDH point between elswift pubkey and privkey.
  # @param [Bitcoin::BIP324::EllSwiftPubkey] their_ell_pubkey Their EllSwift public key.
  # @param [Bitcoin::BIP324::EllSwiftPubkey] our_ell_pubkey Our EllSwift public key.
  # @param [String] priv_key private key with hex format.
  # @param [Boolean] initiating Whether your initiator or not.
  # @return [String] x coordinate with hex format.
  # @raise [Secp256k1::Error] If secret is invalid or hashfp return 0.
  def ellswift_ecdh_xonly(their_ell_pubkey, our_ell_pubkey, priv_key, initiating)
    with_context(flags: SECP256K1_CONTEXT_SIGN) do |context|
      output = FFI::MemoryPointer.new(:uchar, 32)
      our_ell_ptr = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, our_ell_pubkey.key)
      their_ell_ptr = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, their_ell_pubkey.key)
      seckey32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [priv_key].pack('H*'))
      hashfp = secp256k1_ellswift_xdh_hash_function_bip324
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

  private

  # Calculate full public key(64 bytes) from public key(32 bytes).
  # @param [String] pub_key x-only public key with hex format(32 bytes).
  # @return [String] x-only public key with hex format(64 bytes).
  # @raise ArgumentError
  def full_pubkey_from_xonly_pubkey(pub_key)
    with_context do |context|
      pubkey = [pub_key].pack('H*')
      raise ArgumentError, "Pubkey size must be #{X_ONLY_PUBKEY_SIZE} bytes." unless pubkey.bytesize == X_ONLY_PUBKEY_SIZE
      xonly_pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
      full_pubkey = FFI::MemoryPointer.new(:uchar, 64)
      raise ArgumentError, 'An invalid public key was specified.' unless secp256k1_xonly_pubkey_parse(context, full_pubkey, xonly_pubkey) == 1
      full_pubkey.read_string(64).unpack1('H*')
    end
  end

  def generate_pubkey_in_context(context, privkey, compressed: true)
    internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
    result = secp256k1_ec_pubkey_create(context, internal_pubkey, [privkey].pack('H*'))
    raise 'error creating pubkey' unless result
    serialize_pubkey_internal(context, internal_pubkey, compressed)
  end

  def sign_ecdsa(data, privkey, extra_entropy)
    with_context do |context|
      privkey = [privkey].pack('H*')
      secret = FFI::MemoryPointer.new(:uchar, privkey.bytesize).put_bytes(0, privkey)
      raise Error, 'priv_key is invalid' unless secp256k1_ec_seckey_verify(context, secret)

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

  def sign_schnorr(data, privkey, aux_rand = nil)
    with_context do |context|
      keypair = [create_keypair(privkey)].pack('H*')
      keypair = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
      signature = FFI::MemoryPointer.new(:uchar, 64)
      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
      aux_rand = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, aux_rand) if aux_rand
      raise Error, 'Failed to generate schnorr signature.' unless secp256k1_schnorrsig_sign32(context, signature, msg32, keypair, aux_rand) == 1
      signature.read_string(64)
    end
  end

  def verify_ecdsa(data, sig, pubkey)
    with_context do |context|
      return false if data.bytesize == 0
      pubkey = [pubkey].pack('H*')
      pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
      internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
      result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pubkey.size)
      return false unless result

      signature = FFI::MemoryPointer.new(:uchar, sig.bytesize).put_bytes(0, sig)
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

  def verify_schnorr(data, sig, pubkey)
    with_context do |context|
      return false if data.bytesize == 0
      pubkey = [full_pubkey_from_xonly_pubkey(pubkey)].pack('H*')
      xonly_pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
      signature = FFI::MemoryPointer.new(:uchar, sig.bytesize).put_bytes(0, sig)
      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
      result = secp256k1_schnorrsig_verify(context, signature, msg32, 32, xonly_pubkey)
      result == 1
    end
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
end

