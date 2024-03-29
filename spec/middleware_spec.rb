# frozen_string_literal: true

require 'spec_helper'
require 'faraday'
require 'mauth/rack'
require 'mauth/fake/rack'
require 'mauth/faraday'

shared_examples MAuth::Middleware do
  it 'uses a given mauth_client if given' do
    mauth_client = double
    expect(mauth_client).to eq(described_class.new(double('app'), mauth_client: mauth_client).mauth_client)
    expect(mauth_client).to eq(described_class.new(double('app'), 'mauth_client' => mauth_client).mauth_client)
  end

  it 'builds a mauth client if not given a mauth_client' do
    mauth_config = { mauth_baseurl: 'http://mauth', mauth_api_version: 'v1' }
    middleware_instance = described_class.new(double('app'), mauth_config)
    expect(mauth_config[:mauth_baseurl]).to eq(middleware_instance.mauth_client.mauth_baseurl)
    expect(mauth_config[:mauth_api_version]).to eq(middleware_instance.mauth_client.mauth_api_version)
  end
end

describe MAuth::Rack do
  let(:res) { [200, {}, ['hello world']] }
  let(:rack_app) { proc { |_env| res } }
  let(:v2_only_authenticate) { false }
  let(:mw) { described_class.new(rack_app, v2_only_authenticate: v2_only_authenticate) }

  describe MAuth::Rack::RequestAuthenticator do
    include_examples MAuth::Middleware

    it 'calls the app without authentication if should_authenticate check indicates not to' do
      mw_auth_false = described_class.new(rack_app, should_authenticate_check: proc { false })
      env = { 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar' }
      expect(mw_auth_false.mauth_client).not_to receive(:authentic?)
      expect(rack_app).to receive(:call).with(env).and_return(res)
      status, _headers, body = mw_auth_false.call(env)
      expect(200).to eq(status)
      expect(['hello world']).to eq(body)
    end

    it 'authenticates if should_authenticate_check is omitted or indicates to' do
      [nil, proc { |_env| true }].each do |should_authenticate_check|
        mw_w_flag = described_class.new(rack_app, should_authenticate_check: should_authenticate_check)
        env = { 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar' }
        expect(mw_w_flag.mauth_client).to receive(:authentic?).and_return(true)
        expect(rack_app).to receive(:call).with(env.merge(
          MAuth::Client::RACK_ENV_APP_UUID_KEY => 'foo',
          'mauth.authentic' => true,
          'mauth.protocol_version' => 1
        )).and_return(res)
        status, _headers, body = mw_w_flag.call(env)
        expect(status).to eq(200)
        expect(body).to eq(['hello world'])
      end
    end

    it 'returns 401 and does not call the app if authentication fails' do
      expect(mw.mauth_client).to receive(:authentic?).and_return(false)
      expect(rack_app).not_to receive(:call)
      status, _headers, body = mw.call({ 'REQUEST_METHOD' => 'GET' })
      expect(401).to eq(status)
      expect(body.join).to match(/Unauthorized/)
    end

    it 'returns 401 with no body if the request method is HEAD and authentication fails' do
      expect(mw.mauth_client).to receive(:authentic?).and_return(false)
      expect(rack_app).not_to receive(:call)
      status, headers, body = mw.call({ 'REQUEST_METHOD' => 'HEAD' })
      expect(headers['Content-Length'].to_i).to be > 0
      expect(401).to eq(status)
      expect([]).to eq(body)
    end

    it 'returns 500 and does not call the app if unable to authenticate' do
      expect(mw.mauth_client).to receive(:authentic?).and_raise(MAuth::UnableToAuthenticateError.new(''))
      expect(rack_app).not_to receive(:call)
      status, _headers, body = mw.call({ 'REQUEST_METHOD' => 'GET' })
      expect(500).to eq(status)
      expect(body.join).to match(/Could not determine request authenticity/)
    end

    context 'the V2_ONLY_AUTHENTICATE flag is true and the request has only v1 headers' do
      let(:v2_only_authenticate) { true }

      it 'returns 401 with an informative message and does not call the app' do
        env = { 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar', 'REQUEST_METHOD' => 'GET' }
        expect(mw.mauth_client).not_to receive(:authentic?)
        expect(rack_app).not_to receive(:call)
        status, headers, body = mw.call(env)
        expect(401).to eq(status)
        expect(headers['Content-Type']).to eq('application/json')
        expect(JSON.parse(body.join)).to eq({
          'type' => 'errors:mauth:missing_v2',
          'title' => 'This service requires mAuth v2 mcc-authentication header. ' \
                     'Upgrade your mAuth library and configure it properly.'
        })
      end
    end
  end

  describe MAuth::Rack::RequestAuthenticationFaker do
    it 'does not call check authenticity for any request by default' do
      env = { 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar' }
      expect(mw.mauth_client).not_to receive(:authentic?)
      expect(rack_app).to receive(:call).with(env.merge({
        MAuth::Client::RACK_ENV_APP_UUID_KEY => 'foo',
        'mauth.authentic' => true,
        'mauth.protocol_version' => 1
      })).and_return(res)
      status, _headers, body = mw.call(env)
      expect(status).to eq(200)
      expect(body).to eq(['hello world'])
    end

    it 'calls the app when the request is set to be authentic' do
      described_class.authentic = true
      env = { 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar' }
      expect(rack_app).to receive(:call).with(env.merge({
        MAuth::Client::RACK_ENV_APP_UUID_KEY => 'foo',
        'mauth.authentic' => true,
        'mauth.protocol_version' => 1
      })).and_return(res)
      status, _headers, body = mw.call(env)
      expect(status).to eq(200)
      expect(body).to eq(['hello world'])
    end

    it 'does not call the app when the request is set to be inauthentic' do
      described_class.authentic = false
      env = { 'REQUEST_METHOD' => 'GET', 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar' }
      mw.call(env)
      expect(rack_app).not_to receive(:call)
    end

    it 'returns appropriate responses when the request is set to be inauthentic' do
      described_class.authentic = false
      env = { 'REQUEST_METHOD' => 'GET', 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar' }
      status, _headers, _body = mw.call(env)
      expect(status).to eq(401)
    end

    it 'after an inauthentic request, the next request is authentic by default' do
      described_class.authentic = false
      env = { 'REQUEST_METHOD' => 'GET', 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar' }
      status, _headers, _body = mw.call(env)
      expect(status).to eq(401)
      status, _headers, _body = mw.call(env)
      expect(status).to eq(200)
    end
  end

  describe MAuth::Rack::ResponseSigner do
    include_examples MAuth::Middleware

    context 'request with v2 headers' do
      let(:env) do
        {
          'HTTP_MCC_AUTHENTICATION' => 'MWSV2 foo:bar;',
          'REQUEST_METHOD' => 'GET',
          'mauth.protocol_version' => 2
        }
      end

      it 'signs the response with only v2' do
        allow(rack_app).to receive(:call).with(env).and_return(res)
        expect(mw.mauth_client).to receive(:signed_v2).with(
            an_instance_of(MAuth::Rack::Response)
          ).and_return(MAuth::Rack::Response.new(*res))
        mw.call(env)
      end
    end

    context 'request with v1 headers' do
      let(:env) do
        {
          'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar',
          'REQUEST_METHOD' => 'GET',
          'mauth.protocol_version' => 1
        }
      end

      it 'signs the response with only v1' do
        allow(rack_app).to receive(:call).with(env).and_return(res)
        expect(mw.mauth_client).to receive(:signed_v1).with(
            an_instance_of(MAuth::Rack::Response)
          ).and_return(MAuth::Rack::Response.new(*res))
        mw.call(env)
      end
    end

    context 'request with invalid headers' do
      let(:env) do
        {
          'HTTP_MCC_AUTHENTICATION' => 'MWSV500 foo:bar;',
          'REQUEST_METHOD' => 'GET'
        }
      end

      it 'signs the response with the default headers' do
        allow(rack_app).to receive(:call).with(env).and_return(res)
        expect(mw.mauth_client).to receive(:signed).with(
            an_instance_of(MAuth::Rack::Response)
          ).and_return(MAuth::Rack::Response.new(*res))
        mw.call(env)
      end
    end
  end

  describe MAuth::Rack::Response do
    let(:status) { 200 }
    let(:headers) { {} }
    let(:body) { %w[hello world] }
    let(:response) { described_class.new(status, headers, body) }

    describe '#status_headers_body' do
      it 'returns status, headers and body' do
        expect(response.status_headers_body).to eq([status, headers, body])
      end
    end

    describe '#attributes_for_signing' do
      it 'returns attributes_for_signing' do
        expect(response.attributes_for_signing).to eq(status_code: 200, body: 'helloworld')
      end
    end

    describe '#merge_headers' do
      it 'merges headers' do
        expect(response.merge_headers('foo' => 'bar').status_headers_body).to eq([status, { 'foo' => 'bar' }, body])
      end
    end
  end
end

describe MAuth::Faraday do
  describe MAuth::Faraday::ResponseAuthenticator do
    include_examples MAuth::Middleware
    let(:faraday_app) do
      proc do
        res = Object.new
        def res.on_complete
          response_env = Faraday::Env.new
          response_env[:status] = 200
          response_env[:response_headers] = { 'x-mws-authentication' => 'MWS foo:bar' }
          response_env[:body] = 'hello world'
          yield(response_env)
        end
        res
      end
    end
    let(:mw) { described_class.new(faraday_app) }

    it 'returns the response with env indicating authenticity when authentic' do
      allow(mw.mauth_client).to receive(:authenticate!)
      res = mw.call({})
      expect(200).to eq(res[:status])
      expect('foo').to eq(res[MAuth::Client::RACK_ENV_APP_UUID_KEY])
      expect(true).to eq(res['mauth.authentic'])
    end

    it 'raises InauthenticError on inauthentic response' do
      allow(mw.mauth_client).to receive(:authenticate!).and_raise(MAuth::InauthenticError.new)
      expect { mw.call({}) }.to raise_error(MAuth::InauthenticError)
    end

    it 'raises UnableToAuthenticateError when unable to authenticate' do
      allow(mw.mauth_client).to receive(:authenticate!).and_raise(MAuth::UnableToAuthenticateError.new)
      expect { mw.call({}) }.to raise_error(MAuth::UnableToAuthenticateError)
    end

    it 'is usable via the name mauth_response_authenticator' do
      # if this doesn't error, that's fine; means it looked up the middleware and is using it
      Faraday::Connection.new do |conn|
        conn.response :mauth_response_authenticator
        conn.adapter Faraday.default_adapter
      end
    end
  end

  describe MAuth::Faraday::RequestSigner do
    include_examples MAuth::Middleware

    it 'is usable via the name mauth_request_signer' do
      # if this doesn't error, that's fine; means it looked up the middleware and is using it
      Faraday::Connection.new do |conn|
        conn.request :mauth_request_signer
        conn.adapter Faraday.default_adapter
      end
    end
  end

  describe MAuth::Faraday::MAuthClientUserAgent do
    let(:fake_app) do
      Class.new do
        def call(env); end
      end
    end
    let(:agent_base) { 'Sallust' }
    let(:app) { fake_app.new }
    let(:middleware) { described_class.new(app, agent_base) }

    it 'sets the User-Agent request header' do
      request_headers = {}
      request_env = {}
      request_env[:request_headers] = request_headers
      middleware.call(request_env)
      expected = "#{agent_base} (MAuth-Client: #{MAuth::VERSION}; Ruby: #{RUBY_VERSION}; platform: #{RUBY_PLATFORM})"
      expect(request_headers['User-Agent']).to eq(expected)
    end
  end
end
