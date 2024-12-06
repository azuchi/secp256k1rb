module Secp256k1
  module MuSig
    class Session
      include Secp256k1
      attr_reader :session
      attr_reader :key_agg_ctx
      attr_reader :agg_nonce
      attr_reader :msg

      # Create signing session.
      # @param [Secp256k1::MuSig::KeyAggContext] key_agg_ctx The key aggregation context.
      # @param [String] agg_nonce An aggregated public nonce.
      # @param [String] msg The message to be signed.
      # @raise [ArgumentError] If invalid arguments specified.
      # @raise [Secp256k1::Error]
      def initialize(key_agg_ctx, agg_nonce, msg)
        raise ArgumentError, 'key_agg_ctx must be KeyAggContext.' unless key_agg_ctx.is_a?(KeyAggContext)
        validate_string!('msg', msg, 32)
        validate_string!('agg_nonce', agg_nonce, 66)
        agg_nonce = hex2bin(agg_nonce)
        msg = hex2bin(msg)
        with_context do |context|
          @session = FFI::MemoryPointer.new(:uchar, 133)
          agg66 = FFI::MemoryPointer.new(:uchar, 66).put_bytes(0, agg_nonce)
          agg_ptr = FFI::MemoryPointer.new(:uchar, 132)
          if secp256k1_musig_aggnonce_parse(context, agg_ptr, agg66) == 0
            raise Error, "secp256k1_musig_aggnonce_parse failed."
          end
          msg_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, msg)
          if secp256k1_musig_nonce_process(context, @session, agg_ptr, msg_ptr, key_agg_ctx.pointer) == 0
            raise Error, "secp256k1_musig_nonce_process arguments invalid."
          end
        end
        @agg_nonce = agg_nonce.unpack1('H*')
        @msg = msg.unpack1('H*')
        @key_agg_ctx = key_agg_ctx
      end

      # Produces a partial signature for a given key pair and secret nonce.
      # @param [String] private_key The private key to sign the message.
      # @return [String] A partial signature.
      # @raise [ArgumentError] If invalid arguments specified.
      # @raise [Secp256k1::Error]
      def partial_sign(sec_nonce, private_key)
        raise ArgumentError, 'key_agg_ctx must be KeyAggContext.' unless key_agg_ctx.is_a?(KeyAggContext)
        validate_string!('sec_nonce', sec_nonce, 132)
        validate_string!('private_key', private_key, 32)
        with_context do |context|
          partial_sig = FFI::MemoryPointer.new(:uchar, 36)
          sec_nonce_ptr = FFI::MemoryPointer.new(:uchar, 132).put_bytes(0, hex2bin(sec_nonce))
          private_key_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hex2bin(private_key))
          key_pair = FFI::MemoryPointer.new(:uchar, 86)
          if secp256k1_keypair_create(context, key_pair, private_key_ptr) == 0
            raise Error, "secp256k1_keypair_create invalid private_key."
          end
          if secp256k1_musig_partial_sign(
            context, partial_sig, sec_nonce_ptr, key_pair, key_agg_ctx.cache.pointer, session) == 0
            raise Error, "secp256k1_musig_partial_sign arguments invalid or sec_nonce has already been used for signing."
          end
          out32 = FFI::MemoryPointer.new(:uchar, 32)
          secp256k1_musig_partial_sig_serialize(context, out32, partial_sig)
          out32.read_string(32).unpack1('H*')
        end
      end

      # Checks that an individual partial signature verifies.
      # @param [String] partial_sig The partial signature to verify, sent by the signer associated with +pub_nonce+ and +public_key+.
      # @param [String] pub_nonce The public nonce of the signer in the signing session.
      # @param [String] public_key The public key of the signer in the signing session.
      # @return [Boolean] The verification result.
      # @raise [ArgumentError] If invalid arguments specified.
      # @raise [Secp256k1::Error]
      def verify_partial_sig(partial_sig, pub_nonce, public_key)
        validate_string!('partial_sig', partial_sig, 32)
        validate_string!('pub_nonce', pub_nonce, 66)
        validate_string!('public_key', public_key, 33)
        with_context do |context|
          sig_ptr = parse_partial_sig(context, partial_sig)
          public_key = FFI::MemoryPointer.new(:uchar, 33).put_bytes(0, hex2bin(public_key))
          pubkey_ptr = FFI::MemoryPointer.new(:uchar, 64)
          raise Error, "pubkey is invalid." unless secp256k1_ec_pubkey_parse(context, pubkey_ptr, public_key, 33) == 1
          pub_nonce = FFI::MemoryPointer.new(:uchar, 66).put_bytes(0, hex2bin(pub_nonce))
          nonce_ptr = FFI::MemoryPointer.new(:uchar, 132)
          if secp256k1_musig_pubnonce_parse(context, nonce_ptr, pub_nonce) == 0
            raise Error, "secp256k1_musig_pubnonce_parse failed."
          end
          secp256k1_musig_partial_sig_verify(context, sig_ptr, nonce_ptr, pubkey_ptr, key_agg_ctx.pointer, session) == 1
        end
      end

      # Aggregates partial signatures
      # @param [Array] partial_sigs Array of partial signatures.
      # @return [String] An aggregated signature.
      # @raise [ArgumentError] If invalid arguments specified.
      # @raise [Secp256k1::Error]
      def aggregate_partial_sigs(partial_sigs)
        raise ArgumentError, "partial_sigs must be Array." unless partial_sigs.is_a?(Array)
        raise ArgumentError, "partial_sigs must not be empty." if partial_sigs.empty?
        with_context do |context|
          sigs_ptr = FFI::MemoryPointer.new(:pointer, partial_sigs.length)
          sigs_ptr.write_array_of_pointer(partial_sigs.map{|partial_sig| parse_partial_sig(context, partial_sig)})
          sig64 = FFI::MemoryPointer.new(:uchar, 64)
          if secp256k1_musig_partial_sig_agg(context, sig64, session, sigs_ptr, partial_sigs.length) == 0
            raise Error, "secp256k1_musig_partial_sig_agg arguments invalid."
          end
          sig64.read_string(64).unpack1('H*')
        end
      end

      private

      def parse_partial_sig(context, partial_sig)
        partial_sig = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hex2bin(partial_sig))
        sig_ptr = FFI::MemoryPointer.new(:uchar, 36)
        if secp256k1_musig_partial_sig_parse(context, sig_ptr, partial_sig) == 0
          raise Error, "secp256k1_musig_partial_sig_parse failed."
        end
        sig_ptr
      end
    end
  end
end