lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'mauth/version'

Gem::Specification.new do |spec|
  spec.name          = 'mauth-client'
  spec.version       = MAuth::VERSION
  spec.authors       = ['Matthew Szenher', 'Aaron Suggs', 'Geoffrey Ducharme', 'Ethan']
  spec.email         = ['mszenher@mdsol.com']
  spec.summary       = 'Sign and authenticate requests and responses with mAuth authentication.'
  spec.description   = 'Client for signing and authentication of requests and responses with mAuth authentication. Includes middleware for Rack and Faraday for incoming and outgoing requests and responses.'
  spec.homepage      = 'https://github.com/mdsol/mauth-client-ruby'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 2.3.0'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'faraday', '~> 0.7'
  spec.add_dependency 'faraday_middleware', '~> 0.9'
  spec.add_dependency 'term-ansicolor', '~> 1.0'
  spec.add_dependency 'coderay', '~> 1.0'
  spec.add_dependency 'rack'
  spec.add_dependency 'dice_bag', '>= 0.9', '< 2.0'

  spec.add_development_dependency 'bundler', '>= 1.17'
  spec.add_development_dependency 'byebug'
  spec.add_development_dependency 'rack-test', '~> 1.1.0'
  spec.add_development_dependency 'rake', '~> 12.0'
  spec.add_development_dependency 'rspec', '~> 3.8'
  spec.add_development_dependency 'simplecov', '~> 0.16'
  spec.add_development_dependency 'timecop', '~> 0.9'
  spec.add_development_dependency 'benchmark-ips', '~> 2.7'
  spec.add_development_dependency 'rubocop', '~> 0.77'
end
