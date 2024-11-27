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
          xonly = FFI::MemoryPointer.new(:uchar, 32)
          secp256k1_xonly_pubkey_serialize(context, xonly, agg_pubkey)
          xonly.read_string(32).unpack1('H*')
        end
      end
    end
  end
end