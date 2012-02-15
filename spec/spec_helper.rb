require 'timecop'
require 'uuidtools'
if (RUBY_VERSION.split('.').map(&:to_i) <=> [1, 9]) >= 0
  require 'simplecov'
  require 'simplecov-gem-adapter'
  SimpleCov.start 'gem'
end

require 'test/unit/assertions'
RSpec::Core::ExampleGroup.send(:include, Test::Unit::Assertions)