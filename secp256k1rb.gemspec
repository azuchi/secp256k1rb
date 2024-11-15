# frozen_string_literal: true

require_relative "lib/secp256k1/version"

Gem::Specification.new do |spec|
  spec.name = "secp256k1rb"
  spec.version = Secp256k1::VERSION
  spec.authors = ["azuchi"]
  spec.email = ["azuchi@chaintope.com"]

  spec.summary = "Ruby binding for libsecp256k1."
  spec.description = spec.summary
  spec.homepage = "https://github.com/azuchi/secp256k1rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  spec.add_dependency "ffi", ">= 1.16.3"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
