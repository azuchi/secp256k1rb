require 'ffi'

module Secp256k1

  # C interface
  module C
    extend FFI::Library

    ffi_lib(ENV['SECP256K1_LIB_PATH'])

    attach_function(:secp256k1_context_create, [:uint], :pointer)
    attach_function(:secp256k1_context_destroy, [:pointer], :void)
    attach_function(:secp256k1_context_randomize, [:pointer, :pointer], :int)
    attach_function(:secp256k1_context_clone, [:pointer], :pointer)
    attach_function(:secp256k1_context_set_error_callback, [:pointer, :pointer, :pointer], :void)
    attach_function(:secp256k1_context_set_illegal_callback, [:pointer, :pointer, :pointer], :void)
    attach_function(:secp256k1_selftest, [], :void)
    # Preallocated context management
    attach_function(:secp256k1_context_preallocated_size, [:uint], :size_t)
    attach_function(:secp256k1_context_preallocated_create, [:pointer, :uint], :pointer)
    attach_function(:secp256k1_context_preallocated_clone_size, [:pointer], :size_t)
    attach_function(:secp256k1_context_preallocated_clone, [:pointer, :pointer], :pointer)
    attach_function(:secp256k1_context_preallocated_destroy, [:pointer], :void)
    attach_function(:secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_seckey_verify, [:pointer, :pointer], :int)
    # EC key arithmetic (tweak/negate/combine/compare/sort)
    attach_function(:secp256k1_ec_seckey_negate, [:pointer, :pointer], :int)
    attach_function(:secp256k1_ec_seckey_tweak_add, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_seckey_tweak_mul, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_negate, [:pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_tweak_add, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_tweak_mul, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_combine, [:pointer, :pointer, :pointer, :size_t], :int)
    attach_function(:secp256k1_ec_pubkey_cmp, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_sort, [:pointer, :pointer, :size_t], :int)
    # Utilities
    attach_function(:secp256k1_tagged_sha256, [:pointer, :pointer, :pointer, :size_t, :pointer, :size_t], :int)
    attach_function(:secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_serialize, [:pointer, :pointer, :pointer, :pointer, :uint], :int)
    attach_function(:secp256k1_ecdsa_signature_serialize_der, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_signature_serialize_compact, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_parse, [:pointer, :pointer, :pointer, :size_t], :int)
    attach_function(:secp256k1_ecdsa_signature_parse_der, [:pointer, :pointer, :pointer, :size_t], :int)
    attach_function(:secp256k1_ecdsa_signature_parse_compact, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_signature_normalize, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_schnorrsig_sign32, [:pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_schnorrsig_sign, [:pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_schnorrsig_sign_custom, [:pointer, :pointer, :pointer, :size_t, :pointer, :pointer], :int)
    attach_function(:secp256k1_schnorrsig_verify, [:pointer, :pointer, :pointer, :size_t, :pointer], :int)
    attach_function(:secp256k1_keypair_create, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_xonly_pubkey_parse, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_sign_recoverable, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_recoverable_signature_serialize_compact, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_recover, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_recoverable_signature_parse_compact, [:pointer, :pointer, :pointer, :int], :int)
    attach_function(:secp256k1_ecdsa_recoverable_signature_convert, [:pointer, :pointer, :pointer], :int)
    # for ECDH module
    attach_function(:secp256k1_ecdh, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_variable(:secp256k1_ecdh_hash_function_sha256, :pointer)
    attach_variable(:secp256k1_ecdh_hash_function_default, :pointer)
    # for EllSwift module
    attach_function(:secp256k1_ellswift_decode, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ellswift_create, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ellswift_encode, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_variable(:secp256k1_ellswift_xdh_hash_function_bip324, :pointer)
    attach_function(:secp256k1_ellswift_xdh, [:pointer, :pointer, :pointer, :pointer, :pointer, :int, :pointer, :pointer], :int)
    # for ExtraKeys module
    attach_function(:secp256k1_xonly_pubkey_serialize, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_xonly_pubkey_cmp, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_xonly_pubkey_from_pubkey, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_xonly_pubkey_tweak_add, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_xonly_pubkey_tweak_add_check, [:pointer, :pointer, :int, :pointer, :pointer], :int)
    attach_function(:secp256k1_keypair_pub, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_keypair_sec, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_keypair_xonly_pub, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_keypair_xonly_tweak_add, [:pointer, :pointer, :pointer], :int)
    # for MuSig module
    attach_function(:secp256k1_musig_pubkey_agg, [:pointer, :pointer, :pointer, :pointer, :size_t], :int)
    attach_function(:secp256k1_musig_pubkey_get, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_pubkey_ec_tweak_add, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_pubkey_xonly_tweak_add, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_nonce_gen, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_nonce_gen_counter, [:pointer, :pointer, :pointer, :uint64, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_pubnonce_parse, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_pubnonce_serialize, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_aggnonce_serialize, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_aggnonce_parse, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_nonce_agg, [:pointer, :pointer, :pointer, :size_t], :int)
    attach_function(:secp256k1_musig_nonce_process, [:pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_partial_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_partial_sig_serialize, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_partial_sig_parse, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_partial_sig_verify, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_musig_partial_sig_agg, [:pointer, :pointer, :pointer, :pointer, :size_t], :int)

    # Pointer to secp256k1_ellswift_xdh_hash_function_bip324 constant.
    # @return [FFI::Pointer]
    def self.ellswift_xdh_hash_function_bip324
      FFI::Pointer.new(secp256k1_ellswift_xdh_hash_function_bip324)
    end

    # Pointer to secp256k1_ecdh_hash_function_sha256 constant (the default ECDH hash function).
    # @return [FFI::Pointer]
    def self.ecdh_hash_function_sha256
      FFI::Pointer.new(secp256k1_ecdh_hash_function_sha256)
    end

    # Pointer to secp256k1_ecdh_hash_function_default constant.
    # @return [FFI::Pointer]
    def self.ecdh_hash_function_default
      FFI::Pointer.new(secp256k1_ecdh_hash_function_default)
    end
  end
end