require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'mauth/request_and_response'
require 'mauth/client'
require 'securerandom'
require 'benchmark/ips'
require 'faraday'
require 'rspec/mocks/standalone'

RSpec::Core::RakeTask.new(:spec)

task default: :spec

class TestSignableRequest < MAuth::Request
  include MAuth::Signed
  attr_accessor :headers

  def merge_headers(headers)
    self.class.new(@attributes_for_signing).tap{|r| r.headers = (@headers || {}).merge(headers) }
  end

  def x_mws_time
    headers['X-MWS-Time']
  end

  def x_mws_authentication
    headers['X-MWS-Authentication']
  end
end

desc 'Runs benchmarks for the library.'
task :benchmark do
  mc = MAuth::Client.new(private_key: OpenSSL::PKey::RSA.generate(2048), app_uuid: SecureRandom.uuid)
  authenticating_mc = MAuth::Client.new(mauth_baseurl: 'http://whatever', mauth_api_version: 'v1')

  stubs = Faraday::Adapter::Test::Stubs.new
  test_faraday = ::Faraday.new do |builder|
    builder.adapter(:test, stubs)
  end
  stubs.post('/mauth/v1/authentication_tickets.json') { [204, {}, []] }
  Faraday.stub(:new) { test_faraday }

  short_body = 'Somewhere in La Mancha, in a place I do not care to remember'
  average_body = short_body * 1_000
  huge_body = average_body * 100

  short_request = TestSignableRequest.new(verb: 'PUT', request_url: '/', body: short_body)
  average_request = TestSignableRequest.new(verb: 'PUT', request_url: '/', body: average_body)
  huge_request = TestSignableRequest.new(verb: 'PUT', request_url: '/', body: huge_body)

  short_signed_request = mc.signed(short_request)
  average_signed_request = mc.signed(average_request)
  huge_signed_request = mc.signed(huge_request)

  Benchmark.ips do |bm|
    bm.report('sign short') { mc.signed(short_request) }
    bm.report('sign average') { mc.signed(average_request) }
    bm.report('sign huge') { mc.signed(huge_request) }
    bm.compare!
  end

  puts "i/s means the number of signatures of a message per second.\n\n\n"

  Benchmark.ips do |bm|
    bm.report('authenticate short') { authenticating_mc.authentic?(short_signed_request) }
    bm.report('authenticate average') { authenticating_mc.authentic?(average_signed_request) }
    bm.report('authenticate huge') { authenticating_mc.authentic?(huge_signed_request) }
    bm.compare!
  end

  puts 'i/s means the number of authentication checks of signatures per second.'

end
