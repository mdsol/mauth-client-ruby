Gem::Specification.new do |s|
  s.name = 'rack-mauth'
  s.version = '1.0.0'

  s.summary = "Rack middleware to perform request authentication for Medidata web services."
  s.description = "This middleware can be used in any rack-based project as middleware to intercept and authenticate requests to selected urls."

  s.authors  = ["Matthew Szenher", "Aaron Suggs", "Geoffrey Ducharme"]
  s.email    = "mszenher@mdsol.com"
  s.homepage = 'https://github.com/mdsol/rack-mauth'

  s.rdoc_options = ["--charset=UTF-8"]
  s.extra_rdoc_files = %w[README.rdoc]

  s.required_rubygems_version = ">= 1.3.6"

  s.add_dependency 'rack'
  s.add_dependency 'rest-client'
  s.add_dependency 'json'
  
  if (RUBY_VERSION.split('.').map(&:to_i) <=> [1, 9]) >= 0
    s.add_development_dependency('ruby-debug19', '0.11.6')
    s.add_development_dependency('simplecov')
    s.add_development_dependency('simplecov-gem-adapter')
  elsif (RUBY_VERSION.split('.').map(&:to_i) <=> [1, 8]) >= 0
    s.add_development_dependency('ruby-debug', '0.10.3')
  else
    raise "Unknown RUBY_VERSION"
  end
  s.add_development_dependency('rspec', '~> 2.7.0')
  s.add_development_dependency('timecop', '0.3.5')

  s.files = `git ls-files`.split("\n")
  s.test_files = `git ls-files -- {spec,tests}/*`.split("\n")
end
