# Generated lovingly by hand
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{mauth-client}
  s.version = File.read('VERSION').chomp

  s.authors = ["Matthew Szenher", "Aaron Suggs", "Geoffrey Ducharme", "Ethan"]
  s.summary = %q{Sign and authenticate requests and responses with mAuth authentication.}
  s.description = %q{Client for signing and authentication of requests and responses with mAuth authentication. Includes middleware for Rack and Faraday for incoding and outgoing requests and responses.}
  s.email = %q{iwong@mdsol.com}
  s.rdoc_options = ["--charset=UTF-8"]
  s.extra_rdoc_files = %w(LICENSE.txt README.rdoc)
  s.files = `git ls-files`.split("\n")

  s.homepage = %q{http://github.com/mdsol/mauth-client}
  s.test_files = `git ls-files -- {spec,tests}/*`.split("\n")

  s.bindir = 'bin'
  s.executables = ['mauth-client', 'mauth-proxy']

  s.add_dependency 'json', '~> 1.7'
  s.add_dependency 'faraday', '~> 0.7'
  s.add_dependency 'faraday_middleware', '~> 0.8'
  s.add_dependency 'term-ansicolor', '~> 1.0'
  s.add_dependency 'coderay', '~> 1.0'
  s.add_dependency 'rack', '~> 1.4'
end
