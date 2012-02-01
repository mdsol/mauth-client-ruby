# Generated lovingly by hand
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{mauth_signer}
  s.version = "1.1.0"

  s.authors = ["Matthew Szenher", "Aaron Suggs", "Geoffrey Ducharme"]
  s.summary = %q{Create and verify signatures for mAuth.}
  s.description = %q{Create and verify signatures (and header content containing such signatures) for use with mAuth, using middlewares for Rack and Faraday.}
  s.email = %q{iwong@mdsol.com}
  s.rdoc_options = ["--charset=UTF-8"]
  s.extra_rdoc_files = %w(LICENSE.txt README.rdoc)
  s.files = `git ls-files`.split("\n")

  s.homepage = %q{http://github.com/mdsol/mauth_signer}
  s.test_files = `git ls-files -- {spec,tests}/*`.split("\n")

  s.add_dependency 'httpclient', '>= 2.2.4'
  s.add_dependency 'json'
  s.add_development_dependency('shoulda', [">= 0"])
  s.add_development_dependency('bundler', ["~> 1.0.0"])
  s.add_development_dependency('rcov')
  s.add_development_dependency('rake')
  s.add_development_dependency('rspec', '~> 2.7.0')
  s.add_development_dependency('timecop', '0.3.5')
  s.add_development_dependency('rack-test')
  if (RUBY_VERSION.split('.').map(&:to_i) <=> [1, 9]) >= 0
    s.add_development_dependency('simplecov')
    s.add_development_dependency('simplecov-gem-adapter')
  end
end
