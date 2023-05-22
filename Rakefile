# frozen_string_literal: true

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
    self.class.new(@attributes_for_signing).tap { |r| r.headers = (@headers || {}).merge(headers) }
  end

  def x_mws_time
    headers['X-MWS-Time']
  end

  def x_mws_authentication
    headers['X-MWS-Authentication']
  end

  def mcc_time
    headers['MCC-Time']
  end

  def mcc_authentication
    headers['MCC-Authentication']
  end
end

desc 'Runs benchmarks for the library.'
task :benchmark do # rubocop:disable Metrics/BlockLength
  private_key = OpenSSL::PKey::RSA.generate(2048)
  public_key = private_key.public_key
  app_uuid = SecureRandom.uuid

  mc = MAuth::Client.new(
    private_key: private_key,
    app_uuid: app_uuid,
    v2_only_sign_requests: false,
    mauth_baseurl: 'http://whatever',
    mauth_api_version: 'v1'
  )

  stubs = Faraday::Adapter::Test::Stubs.new
  test_faraday = Faraday.new do |builder|
    builder.adapter(:test, stubs)
  end
  stubs.post('/mauth/v1/authentication_tickets.json') { [204, {}, []] }
  stubs.get("/mauth/v1/security_tokens/#{app_uuid}.json") do
    [200, {}, JSON.generate({ 'security_token' => { 'public_key_str' => public_key.to_s } })]
  end
  allow(Faraday).to receive(:new).and_return(test_faraday)

  short_body = 'Somewhere in La Mancha, in a place I do not care to remember'
  average_body = short_body * 1_000
  huge_body = average_body * 100

  qs = 'don=quixote&quixote=don'

  puts <<-MSG

    A short request has a body of 60 chars.
    An average request has a body of 60,000 chars.
    A huge request has a body of 6,000,000 chars.
    A qs request has a body of 60 chars and a query string with two k/v pairs.

  MSG

  short_request = TestSignableRequest.new(verb: 'PUT', request_url: '/', body: short_body)
  qs_request = TestSignableRequest.new(verb: 'PUT', request_url: '/', body: short_body, query_string: qs)
  average_request = TestSignableRequest.new(verb: 'PUT', request_url: '/', body: average_body)
  huge_request = TestSignableRequest.new(verb: 'PUT', request_url: '/', body: huge_body)

  v1_short_signed_request = mc.signed_v1(short_request)
  v1_average_signed_request = mc.signed_v1(average_request)
  v1_huge_signed_request = mc.signed_v1(huge_request)

  v2_short_signed_request = mc.signed_v2(short_request)
  v2_qs_signed_request = mc.signed_v1(qs_request)
  v2_average_signed_request = mc.signed_v2(average_request)
  v2_huge_signed_request = mc.signed_v1(huge_request)

  Benchmark.ips do |bm|
    bm.report('v1-sign-short') { mc.signed_v1(short_request) }
    bm.report('v2-sign-short') { mc.signed_v2(short_request) }
    bm.report('both-sign-short') { mc.signed(short_request) }
    bm.report('v2-sign-qs') { mc.signed_v2(qs_request) }
    bm.report('both-sign-qs') { mc.signed(qs_request) }
    bm.report('v1-sign-average') { mc.signed_v1(average_request) }
    bm.report('v2-sign-average') { mc.signed_v2(average_request) }
    bm.report('both-sign-average') { mc.signed(average_request) }
    bm.report('v1-sign-huge') { mc.signed_v1(huge_request) }
    bm.report('v2-sign-huge') { mc.signed_v2(huge_request) }
    bm.report('both-sign-huge') { mc.signed(huge_request) }
    bm.compare!
  end

  puts "i/s means the number of signatures of a message per second.\n\n\n"

  Benchmark.ips do |bm|
    bm.report('v1-authenticate-short') { mc.authentic?(v1_short_signed_request) }
    bm.report('v2-authenticate-short') { mc.authentic?(v2_short_signed_request) }
    bm.report('v2-authenticate-qs') { mc.authentic?(v2_qs_signed_request) }
    bm.report('v1-authenticate-average') { mc.authentic?(v1_average_signed_request) }
    bm.report('v2-authenticate-average') { mc.authentic?(v2_average_signed_request) }
    bm.report('v1-authenticate-huge') { mc.authentic?(v1_huge_signed_request) }
    bm.report('v2-authenticate-huge') { mc.authentic?(v2_huge_signed_request) }
    bm.compare!
  end

  puts 'i/s means the number of authentication checks of signatures per second.'
end
