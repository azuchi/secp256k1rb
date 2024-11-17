# secp256k1rb

This is a Ruby binding for Bitcoin Core's [secp256k1 library](https://github.com/bitcoin-core/secp256k1/).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'secp256k1rb', require: 'secp256k1'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install secp256k1rb

## Usage

To use this library, you need to specify the path of the secp256k1 shared library in environment variable
`SECP256K1_LIB_PATH`, e.g: `$ export SECP256K1_LIB_PATH=/var/local/lib/libsecp256k1.so`.

Note: This library also implements the recovery module, so you must have built the secp256k1 library with the
`--enable-module-recovery` option.

By including the Secp256k1 module, you can use the features provided by the `libsepc256k1` library. For example:

```ruby
require 'secp256k1'

include Secp256k1

generate_key_pair
=> ["e00c2ae99e59b5262be3d507d026081f0e6cf9972ffdd4f2d45a390f7a41b053", "027e0f70b540d627422cf7bb77d86ae1bb6829c80104dd48dc2539e6277ea25624"]
```

See [here](https://www.rubydoc.info/gems/secp256k1rb/Secp256k1) for available methods.
In addition, the following modules are also included, so you can use them as they are.

* [Recover](https://www.rubydoc.info/gems/secp256k1rb/Secp256k1/Recover)
* [SchnorrSig](https://www.rubydoc.info/gems/secp256k1rb/Secp256k1/SchnorrSig)
* [EllSwift](https://www.rubydoc.info/gems/secp256k1rb/Secp256k1/EllSwift)
