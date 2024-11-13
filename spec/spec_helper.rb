# frozen_string_literal: true

host_os = RbConfig::CONFIG['host_os']
case host_os
when /linux/
  ENV['SECP256K1_LIB_PATH'] = ENV['TEST_LIBSECP256K1_PATH'] || File.expand_path('lib/libsecp256k1.so', File.dirname(__FILE__))
else
  if ENV['LIBSECP_PATH']
    ENV['SECP256K1_LIB_PATH'] = ENV['TEST_LIBSECP256K1_PATH']
  else
    raise "To run this test, environment variable \"TEST_LIBSECP256K1_PATH\" must specify the path to a valid libsecp256k1 library."
  end
end

require "secp256k1"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

RSpec.shared_context 'common setup' do
  let(:target) do
    class Target
      include Secp256k1
    end.new
  end
end