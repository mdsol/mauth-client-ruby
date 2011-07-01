# Generated lovingly by hand
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{mauth_signer}
  s.version = "0.5.0"

  s.authors = ["Matthew Szenher", 'Aaron Suggs']
  s.summary = %q{Create HMAC signatures for mAuth.}
  s.description = %q{Create signatures (and header content containing such signatures) for use with mAuth.  Signatures are created from HMAC-SHA1'd request data. }
  s.email = %q{iwong@mdsol.com}
  s.extra_rdoc_files = %w(LICENSE.txt README.rdoc)
  s.files = `git ls-files`.split("\n")

  s.homepage = %q{http://github.com/mdsol/mauth_signer}
  s.test_files = `git ls-files -- {spec,tests}/*`.split("\n")

  s.add_development_dependency('shoulda', [">= 0"])
  s.add_development_dependency('bundler', ["~> 1.0.0"])
  s.add_development_dependency('rcov')
  s.add_development_dependency('rake')
end

