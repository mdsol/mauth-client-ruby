require 'spec_helper'
require 'mauth/client'
require 'mauth/authenticators/remote_request_authenticator'
require_relative '../shared_examples/authenticators.rb'

describe MAuth::Client::RemoteRequestAuthenticator do
  describe '#authentic?' do
    let(:stubs) { Faraday::Adapter::Test::Stubs.new }
    let(:authenticating_mc) do
      MAuth::Client.new(
        mauth_baseurl: 'http://whatever',
        mauth_api_version: 'v1',
        authenticate_with_only_v2: authenticate_with_only_v2
      )
    end
    let(:test_faraday) do
      ::Faraday.new do |builder|
        builder.adapter(:test, stubs)
      end
    end
    let(:query_string) { 'key=value&coolkey=coolvalue' }
    let(:qs_request) do
      TestSignableRequest.new(
        verb: 'PUT',
        request_url: '/',
        body: 'himom',
        query_string: query_string
      )
    end

    before do
      expect(authenticating_mc).to be_kind_of(MAuth::Client::RemoteRequestAuthenticator)
      stubs.post('/mauth/v1/authentication_tickets.json') { [204, {}, []] }
      allow(::Faraday).to receive(:new).and_return(test_faraday)
    end

    include_examples MAuth::Client::Authenticator

    it 'considers a request to be authentic if mauth reports it so' do
      signed_request = client.signed(request)
      expect(authenticating_mc.authentic?(signed_request)).to be_truthy
    end

    it 'considers a request to be inauthentic if mauth reports it so' do
      stubs.instance_eval{ @stack.clear } #HAX
      stubs.post('/mauth/v1/authentication_tickets.json') { [412, {}, []] }
      signed_request = client.signed(request)
      expect(authenticating_mc.authentic?(signed_request)).to be_falsey
    end

    context 'when authenticating with v2' do
      it 'includes the query string and token in the request' do
        expect(test_faraday).to receive(:post).with(
          '/mauth/v1/authentication_tickets.json',
          'authentication_ticket' => hash_including('query_string' => query_string, 'token' => 'MWSV2')
        ).and_return(double('resp', status: 200))

        signed_request = client.signed(qs_request)
        authenticating_mc.authentic?(signed_request)
      end
    end
  end
end
