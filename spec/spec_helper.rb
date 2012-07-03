require 'timecop'
require 'uuidtools'
require 'json'

if (RUBY_VERSION.split('.').map(&:to_i) <=> [1, 9]) >= 0
  require 'simplecov'
  require 'simplecov-gem-adapter'
  SimpleCov.start 'gem'
end

module MAuth
  module Assertions
    # takes an error class and error message. the latter may be a string, which will match if it is 
    # a substring of the actual error message, or regexp, which will be tested against the actual message. 
    #
    # may optionally take an assertion failure message. 
    def assert_raise_with_message(error_class, error_message, assertion_fail_message=nil, &block)
      begin
        yield
      rescue Exception => e
        exception = e
      end
      assertion_fail_message ||= "Expected block to raise #{error_class} with message #{error_message.inspect}. "
      if exception
        assertion_fail_message += "\nUnexpected error raised: #{exception.inspect}."
      else
        assertion_fail_message += "\nNothing was raised."
      end
      # checks the message with String#[] to match either regexp or string 
      assert(exception.class <= error_class && exception.message[error_message], assertion_fail_message)
    end
  end
end

require 'test/unit/assertions'
RSpec::Core::ExampleGroup.send(:include, Test::Unit::Assertions)
RSpec::Core::ExampleGroup.send(:include, MAuth::Assertions)
