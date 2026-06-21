## [Unreleased]

## [0.3.0]

- Support secp256k1 v0.7.1.
- Add FFI bindings for the full v0.7.1 public C API.
- Add `Secp256k1::Key` module: EC key arithmetic (`tweak_add_seckey`/`tweak_mul_seckey`/`negate_seckey`, `tweak_add_pubkey`/`tweak_mul_pubkey`/`negate_pubkey`, `combine_pubkeys`), x-only public key operations (`xonly_pubkey_from_pubkey`, `xonly_tweak_add_pubkey`, `xonly_tweak_add_check?`) and key pair accessors (`keypair_to_seckey`/`keypair_to_pubkey`/`keypair_to_xonly_pubkey`).
  Also adds `compare_pubkey`/`sort_pubkeys`/`compare_xonly_pubkey` and `keypair_xonly_tweak_add`.
- Add `Secp256k1::ECDH` module: `ecdh`.
- Add compact ECDSA signature conversion: `ecdsa_signature_to_compact` / `ecdsa_signature_from_compact`.
- Add `tagged_sha256` (BIP-340 tagged hash).
- Add `Secp256k1::EllSwift#ellswift_encode`.
- Add `Secp256k1::Recover#recoverable_signature_to_ecdsa`.
- Add `Secp256k1::SchnorrSig#sign_schnorr_custom` / `#verify_schnorr_custom` for variable-length messages.
- Add `Secp256k1::MuSig#generate_musig_nonce_counter` (deterministic counter-based nonce generation).

## [0.1.0] - 2024-05-07

- Initial release
