require 'spec_helper'
require 'digest'
require 'securerandom'

# These specs exercise the lower-level FFI bindings that have no high-level Ruby wrapper
# (context cloning, preallocated context management, self-test, callback setters and the
# deprecated secp256k1_schnorrsig_sign alias).
RSpec.describe Secp256k1::C do
  include_context "common setup"

  let(:flags) { Secp256k1::CONTEXT_SIGN | Secp256k1::CONTEXT_VERIFY }
  let(:seckey) do
    # A valid 32-byte private key (1).
    FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, "\x00" * 31 + "\x01")
  end

  describe '.secp256k1_selftest' do
    it 'runs without raising' do
      expect { described_class.secp256k1_selftest }.not_to raise_error
    end
  end

  describe '.secp256k1_context_clone' do
    it 'clones a context that remains usable' do
      ctx = described_class.secp256k1_context_create(flags)
      clone = described_class.secp256k1_context_clone(ctx)
      expect(clone.null?).to be false
      expect(described_class.secp256k1_ec_seckey_verify(clone, seckey)).to eq(1)
      described_class.secp256k1_context_destroy(clone)
      described_class.secp256k1_context_destroy(ctx)
    end
  end

  describe 'preallocated context' do
    it 'creates, clones and destroys a context in caller-provided memory' do
      size = described_class.secp256k1_context_preallocated_size(flags)
      expect(size).to be > 0

      buf = FFI::MemoryPointer.new(:uchar, size)
      ctx = described_class.secp256k1_context_preallocated_create(buf, flags)
      expect(ctx.null?).to be false
      expect(described_class.secp256k1_ec_seckey_verify(ctx, seckey)).to eq(1)

      clone_size = described_class.secp256k1_context_preallocated_clone_size(ctx)
      expect(clone_size).to eq(size)

      clone_buf = FFI::MemoryPointer.new(:uchar, clone_size)
      clone = described_class.secp256k1_context_preallocated_clone(ctx, clone_buf)
      expect(clone.null?).to be false
      expect(described_class.secp256k1_ec_seckey_verify(clone, seckey)).to eq(1)

      expect { described_class.secp256k1_context_preallocated_destroy(clone) }.not_to raise_error
      expect { described_class.secp256k1_context_preallocated_destroy(ctx) }.not_to raise_error
    end
  end

  describe 'callback setters' do
    it 'sets custom and default error/illegal callbacks without raising' do
      ctx = described_class.secp256k1_context_create(flags)
      callback = FFI::Function.new(:void, [:pointer, :pointer]) { |_message, _data| }
      expect { described_class.secp256k1_context_set_error_callback(ctx, callback, nil) }.not_to raise_error
      expect { described_class.secp256k1_context_set_illegal_callback(ctx, callback, nil) }.not_to raise_error
      # Passing NULL resets to the default handler.
      expect { described_class.secp256k1_context_set_error_callback(ctx, nil, nil) }.not_to raise_error
      expect { described_class.secp256k1_context_set_illegal_callback(ctx, nil, nil) }.not_to raise_error
      described_class.secp256k1_context_destroy(ctx)
    end
  end

  describe '.secp256k1_schnorrsig_sign (deprecated)' do
    it 'produces a valid signature' do
      sk, pk = target.generate_key_pair
      xonly, = target.xonly_pubkey_from_pubkey(pk)
      keypair = [target.create_keypair(sk)].pack('H*')
      msg = Digest::SHA256.digest('message')

      ctx = described_class.secp256k1_context_create(flags)
      randomize = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.bytes(32))
      described_class.secp256k1_context_randomize(ctx, randomize)

      sig = FFI::MemoryPointer.new(:uchar, 64)
      msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, msg)
      keypair_ptr = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
      expect(described_class.secp256k1_schnorrsig_sign(ctx, sig, msg32, keypair_ptr, nil)).to eq(1)
      described_class.secp256k1_context_destroy(ctx)

      expect(target.verify_schnorr(msg, sig.read_string(64), xonly)).to be true
    end
  end
end
