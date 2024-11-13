require 'ffi'

module Secp256k1

  # C interface
  module C
    extend FFI::Library

    ffi_lib(ENV['SECP256K1_LIB_PATH'])

    attach_function(:secp256k1_context_create, [:uint], :pointer)
    attach_function(:secp256k1_context_destroy, [:pointer], :void)
    attach_function(:secp256k1_context_randomize, [:pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_seckey_verify, [:pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_serialize, [:pointer, :pointer, :pointer, :pointer, :uint], :int)
    attach_function(:secp256k1_ecdsa_signature_serialize_der, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ec_pubkey_parse, [:pointer, :pointer, :pointer, :size_t], :int)
    attach_function(:secp256k1_ecdsa_signature_parse_der, [:pointer, :pointer, :pointer, :size_t], :int)
    attach_function(:secp256k1_ecdsa_signature_normalize, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_schnorrsig_sign32, [:pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_schnorrsig_verify, [:pointer, :pointer, :pointer, :size_t, :pointer], :int)
    attach_function(:secp256k1_keypair_create, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_xonly_pubkey_parse, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_sign_recoverable, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_recoverable_signature_serialize_compact, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_recover, [:pointer, :pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ecdsa_recoverable_signature_parse_compact, [:pointer, :pointer, :pointer, :int], :int)
    attach_function(:secp256k1_ellswift_decode, [:pointer, :pointer, :pointer], :int)
    attach_function(:secp256k1_ellswift_create, [:pointer, :pointer, :pointer, :pointer], :int)
    # Define function pointer
    callback(:secp256k1_ellswift_xdh_hash_function, [:pointer, :pointer, :pointer, :pointer, :pointer], :int)
    attach_variable(:secp256k1_ellswift_xdh_hash_function_bip324, :secp256k1_ellswift_xdh_hash_function)
    attach_function(:secp256k1_ellswift_xdh, [:pointer, :pointer, :pointer, :pointer, :pointer, :int, :pointer, :pointer], :int)

  end
end