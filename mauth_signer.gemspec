# Generated lovingly by hand
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{mauth_signer}
  s.version = "0.2.0"

  s.authors = ["Matthew Szenher", 'Aaron Suggs']
  s.description = %q{TODO: longer description of your gem}
  s.email = %q{iwong@mdsol.com}
  s.extra_rdoc_files = %w(LICENSE.txt README.rdoc)
  s.files = `git ls-files`.split("\n")

  s.homepage = %q{http://github.com/mdsol/mauth_signer}
  s.summary = %q{Create canonical strings and signatures for shared-secret-style authentication for apps associated with Medidata Solutions.}
  s.test_files = `git ls-files -- {spec,tests}/*`.split("\n")

  s.add_development_dependency('shoulda', [">= 0"])
  s.add_development_dependency('bundler', ["~> 1.0.0"])
  s.add_development_dependency('jeweler', ["~> 1.5.2"])
  s.add_development_dependency('rcov', [">= 0"])
end

