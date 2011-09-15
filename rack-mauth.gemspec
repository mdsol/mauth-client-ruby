Gem::Specification.new do |s|
  s.name = 'rack-mauth'
  s.version = '0.0.1'

  s.summary = "Rack middelware to perform request authentication for Medidata web services."
  s.description = "Like the summary says."

  s.authors  = ["Matthew Szenher", "Aaron Suggs"]
  s.email    = "mszenher@mdsol.com"
  s.homepage = 'https://github.com/mdsol/rack-mauth'

  s.rdoc_options = ["--charset=UTF-8"]
  s.extra_rdoc_files = %w[README.rdoc]

  s.required_rubygems_version = ">= 1.3.6"
  
  s.add_dependency "bundler", ">= 1.0.0"
  s.add_dependency 'rack'
  #s.add_dependency('mauth_signer', '0.5.3')
  
  s.add_development_dependency('ruby-debug', '0.10.3')
  s.add_development_dependency('rspec', '2.6.0')
  s.add_development_dependency('timecop', '0.3.5')

  s.files = `git ls-files`.split("\n")
  s.test_files = `git ls-files -- {spec,tests}/*`.split("\n")
end