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
  s.executables = 'mauth-client'

  s.add_dependency 'json'
  s.add_dependency 'faraday', '~> 0.7'
  s.add_dependency 'faraday_middleware'
  s.add_dependency 'term-ansicolor'
  s.add_development_dependency('shoulda', [">= 0"])
  s.add_development_dependency('rake')
  s.add_development_dependency('rspec', '~> 2.7.0')
  s.add_development_dependency('timecop', '0.3.5')
  s.add_development_dependency('rack-test')
  if (RUBY_VERSION.split('.').map(&:to_i) <=> [1, 9]) >= 0
    s.add_development_dependency('simplecov')
    s.add_development_dependency('simplecov-gem-adapter')
  else
    s.add_development_dependency('rcov')
  end
end
