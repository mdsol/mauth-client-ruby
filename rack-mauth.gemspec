Gem::Specification.new do |s|
  s.name = 'rack-mauth'
  s.version = '0.1.1'

  s.summary = "Rack middleware to perform request authentication for Medidata web services."
  s.description = "This middleware can be used in any rack-based project as middleware to intercept and authenticate requests to selected urls."

  s.authors  = ["Matthew Szenher", "Aaron Suggs", "Geoffrey Ducharme"]
  s.email    = "mszenher@mdsol.com"
  s.homepage = 'https://github.com/mdsol/rack-mauth'

  s.rdoc_options = ["--charset=UTF-8"]
  s.extra_rdoc_files = %w[README.rdoc]

  s.required_rubygems_version = ">= 1.3.6"

  s.add_dependency 'rack'

  if RUBY_VERSION['1.9']
    s.add_development_dependency('ruby-debug19', '0.11.6')
  elsif RUBY_VERSION['1.8']
    s.add_development_dependency('ruby-debug', '0.10.3')
  else
    raise "Unknown RUBY_VERSION"
  end
  s.add_development_dependency('rspec', '2.6.0')
  s.add_development_dependency('timecop', '0.3.5')

  s.files = `git ls-files`.split("\n")
  s.test_files = `git ls-files -- {spec,tests}/*`.split("\n")
end
