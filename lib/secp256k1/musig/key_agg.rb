module Secp256k1
  module MuSig

    # Opaque data structure that caches information about public key aggregation.
    class KeyAggCache < FFI::Struct
      layout :data, [:uchar, 197]
    end

    # Key aggregation context class.
    class KeyAggContext
      include Secp256k1

      attr_reader :cache

      # Constructor.
      # @param [Secp256k1::MuSig::KeyAggCache] key_agg_cache Key aggregation cache.
      # @raise [ArgumentError] If invalid arguments specified.
      def initialize(key_agg_cache)
        raise ArgumentError, "key_agg_cache must be Secp256k1::KeyAggCache." unless key_agg_cache.is_a?(Secp256k1::KeyAggCache)
        @cache = key_agg_cache
      end

      # Get aggregate public key.
      # @return [String] An aggregated public key.
      def aggregate_public_key
        with_context do |context|
          agg_pubkey = FFI::MemoryPointer.new(:uchar, 64)
          if secp256k1_musig_pubkey_get(context, agg_pubkey, cache.pointer) == 0
            raise Error, "secp256k1_musig_pubkey_get arguments invalid."
          end
          serialize_pubkey(context, agg_pubkey)
        end
      end

      # Apply ordinary "EC" tweaking to a public key.
      # @param [String] tweak Tweak value to tweak the aggregated key.
      # @param [Boolean] xonly Apply x-only tweaking or not.
      # @return [String] Tweaked x-only public key with hex format.
      # @raise [ArgumentError] If invalid arguments specified.
      # @raise [Secp256k1::Error]
      def tweak_add(tweak, xonly: false)
        validate_string!("tweak", tweak, 32)
        with_context do |context|
          tweak_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, hex2bin(tweak))
          pubkey_ptr = FFI::MemoryPointer.new(:uchar, 64)
          if xonly
            if secp256k1_musig_pubkey_xonly_tweak_add(context, pubkey_ptr, cache.pointer, tweak_ptr) == 0
              raise Error, "secp256k1_musig_pubkey_tweak_add arguments invalid."
            end
          else
            if secp256k1_musig_pubkey_ec_tweak_add(context, pubkey_ptr, cache.pointer, tweak_ptr) == 0
              raise Error, "secp256k1_musig_pubkey_tweak_add arguments invalid."
            end
          end
          serialize_pubkey(context, pubkey_ptr)
        end
      end

      # Get KeyAggCache pointer.
      # @return [FFI::MemoryPointer]
      def pointer
        cache.pointer
      end

      private

      def serialize_pubkey(context, pubkey_ptr)
        xonly = FFI::MemoryPointer.new(:uchar, 32)
        secp256k1_xonly_pubkey_serialize(context, xonly, pubkey_ptr)
        xonly.read_string(32).unpack1('H*')
      end
    end
  end
end