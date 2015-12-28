# Generated lovingly by hand
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{mauth-client}
  s.version = File.read('VERSION').chomp

  s.authors = ["Matthew Szenher", "Aaron Suggs", "Geoffrey Ducharme", "Ethan"]
  s.summary = %q{Sign and authenticate requests and responses with mAuth authentication.}
  s.description = %q{Client for signing and authentication of requests and responses with mAuth authentication. Includes middleware for Rack and Faraday for incoding and outgoing requests and responses.}
  s.email = %q{iwong@mdsol.com mszenher@mdsol.com}
  s.rdoc_options = ["--charset=UTF-8"]
  s.extra_rdoc_files = %w(LICENSE.txt README.rdoc)
  s.files = `git ls-files`.split("\n")

  s.homepage = %q{http://github.com/mdsol/mauth-client}
  s.test_files = `git ls-files -- {spec,tests}/*`.split("\n")

  s.bindir = 'bin'
  s.executables = ['mauth-client', 'mauth-proxy']

  # TODO:  remove or attenuate version dependencies wherever possible so mauth-client can
  # be consumed by more apps.
  s.add_dependency 'faraday', '~> 0.7'
  s.add_dependency 'faraday_middleware', '~> 0.9'
  s.add_dependency 'term-ansicolor', '~> 1.0'
  s.add_dependency 'coderay', '~> 1.0'
  s.add_dependency 'rack'
  s.add_dependency 'dice_bag', '>= 0.9', '< 2.0'

  s.add_development_dependency 'bundler', '~> 1.10'
  s.add_development_dependency 'rake', '~> 10.0'
  s.add_development_dependency 'rspec', '~> 3.4.0'
end
