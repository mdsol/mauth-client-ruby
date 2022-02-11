# frozen_string_literal: true

require 'spec_helper'
require 'faraday'
require 'mauth/client'

describe MAuth::Client::LocalAuthenticator::SecurityTokenCacher do
  subject { described_class.new(client) }
  let(:client) do
    MAuth::Client.new(
      mauth_baseurl: 'http://whatever',
      mauth_api_version: 'v1',
      private_key: OpenSSL::PKey::RSA.generate(2048),
      app_uuid: 'authenticator'
    )
  end

  describe '#get' do
    let(:service_app_uuid) { '077dcb2b-f476-4069-adf4-f75c15018d65' }
    let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:status) { 200 }
    let(:headers) { {} }
    let(:security_token) { { 'security_token' => { 'public_key_str' => signing_key.public_key.to_s } } }
    let(:response_body) { JSON.generate(security_token) }

    before do
      stub_request(:get, "http://whatever/mauth/v1/security_tokens/#{service_app_uuid}.json").to_return(
        status: status,
        headers: headers,
        body: response_body
      )
    end

    shared_examples_for 'Faraday errors' do |faraday_error|
      before do
        allow_any_instance_of(Faraday::Connection).to receive(:get).and_raise(faraday_error.new(''))
      end

      it 'logs and raises UnableToAuthenticateError' do
        expect(client.logger).to receive(:error)
          .with(/Unable to authenticate with MAuth. Exception mAuth service did not respond; received/)
        expect { subject.get(service_app_uuid) }.to raise_error(MAuth::UnableToAuthenticateError)
      end
    end

    context 'when response status is 200' do
      it 'returns security_token' do
        expect(subject.get(service_app_uuid)).to eq(security_token)
      end
    end

    context 'malicious app_uuid' do
      let(:service_app_uuid) { "!#{$&}'()*+,/:;=?@[]" }
      let(:escaped_app_uuid) { '%21%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D' }

      before do
        stub_request(:get, "http://whatever/mauth/v1/security_tokens/#{escaped_app_uuid}.json").to_return(
          status: status,
          headers: headers,
          body: response_body
        )
      end

      it 'escapes app_uuid' do
        expect_any_instance_of(Faraday::Connection)
          .to receive(:get).with("/mauth/v1/security_tokens/#{escaped_app_uuid}.json")
          .and_call_original

        subject.get(service_app_uuid)
      end
    end

    context 'when faraday error occurs' do
      include_examples 'Faraday errors', Faraday::ConnectionFailed
      include_examples 'Faraday errors', Faraday::TimeoutError
    end

    context 'when response body is not JSON' do
      let(:response_body) { 'plain text' }

      it 'logs and raises UnableToAuthenticateError' do
        expect(client.logger).to receive(:error)
          .with(/Unable to authenticate with MAuth. Exception mAuth service responded with unparseable json/)
        expect { subject.get(service_app_uuid) }.to raise_error(MAuth::UnableToAuthenticateError)
      end
    end

    context 'when response status is 404' do
      let(:status) { 404 }

      it 'raises InauthenticError' do
        expect { subject.get(service_app_uuid) }
          .to raise_error(
            MAuth::InauthenticError,
            "mAuth service responded with 404 looking up public key for #{service_app_uuid}"
          )
      end
    end

    context 'when response status is not 404' do
      let(:status) { 500 }

      it 'raises UnableToAuthenticateError' do
        expect { subject.get(service_app_uuid) }.to raise_error(MAuth::UnableToAuthenticateError)
      end
    end

    describe 'caching' do
      let(:headers) do
        {
          'Cache-Control' => 'max-age=300, private',
          'ETag' => 'W"e9d1e3499087ff67e169e9ee0034f5c9'
        }
      end

      before do
        Timecop.freeze(Time.now)

        stub_request(:get, "http://whatever/mauth/v1/security_tokens/#{service_app_uuid}.json").to_return(
          status: status,
          headers: headers,
          body: response_body
        ).then.to_return(
          status: status,
          body: '{}'
        )
      end

      after do
        Timecop.return
      end

      it 'caches the response' do
        expect(subject.get(service_app_uuid)).to eq(security_token)
        expect(subject.get(service_app_uuid)).to eq(security_token)
      end

      it 'retrives again once the cache is expired' do
        expect(subject.get(service_app_uuid)).to eq(security_token)
        Timecop.freeze(Time.now + 301)
        expect(subject.get(service_app_uuid)).to be_empty
      end
    end
  end
end
