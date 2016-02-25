require 'spec_helper'
require 'faraday'
require 'mauth/rack'
require 'mauth/fake/rack'
require 'mauth/faraday'

shared_examples MAuth::Middleware do
  it 'uses a given mauth_client if given' do
    mauth_client = double
    expect(mauth_client).to eq(described_class.new(double('app'), :mauth_client => mauth_client).mauth_client)
    expect(mauth_client).to eq(described_class.new(double('app'), 'mauth_client' => mauth_client).mauth_client)
  end
  it 'builds a mauth client if not given a mauth_client' do
    mauth_config = {:mauth_baseurl => 'http://mauth', :mauth_api_version => 'v1'}
    middleware_instance = described_class.new(double('app'), mauth_config)
    expect(mauth_config[:mauth_baseurl]).to eq(middleware_instance.mauth_client.mauth_baseurl)
    expect(mauth_config[:mauth_api_version]).to eq(middleware_instance.mauth_client.mauth_api_version)
  end
end
describe MAuth::Rack::RequestAuthenticator do
  include_examples MAuth::Middleware
  before do
    @res = [200, {}, ['hello world']]
    @rack_app = proc{|env| @res }
  end
  it 'calls the app without authentication if should_authenticate check indicates not to' do
    mw = described_class.new(@rack_app, :should_authenticate_check => proc { false })
    env = double
    expect(mw.mauth_client).not_to receive(:authentic?)
    expect(@rack_app).to receive(:call).with(env).and_return(@res)
    status, headers, body = mw.call(env)
    expect(200).to eq(status)
    expect(['hello world']).to eq(body)
  end
  it 'authenticates if should_authenticate_check is omitted or indicates to' do
    [nil, proc {|env| true }].each do |should_authenticate_check|
      mw = described_class.new(@rack_app, :should_authenticate_check => should_authenticate_check)
      env = {'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar'}
      expect(mw.mauth_client).to receive(:authentic?).and_return(true)
      expect(@rack_app).to receive(:call).with(env.merge('mauth.app_uuid' => 'foo', 'mauth.authentic' => true)).and_return(@res)
      status, headers, body = mw.call(env)
      expect(status).to eq(200)
      expect(body).to eq(['hello world'])
    end
  end
  it 'returns 401 and does not call the app if authentication fails' do
    mw = described_class.new(@rack_app)
    expect(mw.mauth_client).to receive(:authentic?).and_return(false)
    expect(@rack_app).not_to receive(:call)
    status, headers, body = mw.call({'REQUEST_METHOD' => 'GET'})
    expect(401).to eq(status)
    expect(body.join).to match(/Unauthorized/)
  end
  it 'returns 401 with no body if the request method is HEAD and authentication fails' do
    mw = described_class.new(@rack_app)
    expect(mw.mauth_client).to receive(:authentic?).and_return(false)
    expect(@rack_app).not_to receive(:call)
    status, headers, body = mw.call({'REQUEST_METHOD' => 'HEAD'})
    expect(headers["Content-Length"].to_i).to be > 0
    expect(401).to eq(status)
    expect([]).to eq(body)
  end
  it 'returns 500 and does not call the app if unable to authenticate' do
    mw = described_class.new(@rack_app)
    expect(mw.mauth_client).to receive(:authentic?).and_raise(MAuth::UnableToAuthenticateError.new(''))
    expect(@rack_app).not_to receive(:call)
    status, headers, body = mw.call({'REQUEST_METHOD' => 'GET'})
    expect(500).to eq(status)
    expect(body.join).to match(/Could not determine request authenticity/)
  end
end

describe MAuth::Rack::RequestAuthenticationFaker do
  before do
    @res = [200, {}, ['hello world']]
    @rack_app = proc{|env| @res }
  end

  it 'does not call check authenticity for any request by default' do
    mw = described_class.new(@rack_app)
    env = {'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar'}
    expect(mw.mauth_client).not_to receive(:authentic?)
    expect(@rack_app).to receive(:call).with(env.merge({'mauth.app_uuid' => 'foo', 'mauth.authentic' => true})).and_return(@res)
    status, headers, body = mw.call(env)
    expect(status).to eq(200)
    expect(body).to eq(['hello world'])
  end

  it 'calls the app when the request is set to be authentic' do
    described_class.authentic = true
    mw = described_class.new(@rack_app)
    env = {'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar'}
    allow(@rack_app).to receive(:call).with(env.merge({'mauth.app_uuid' => 'foo', 'mauth.authentic' => true})).and_return(@res)
    status, headers, body = mw.call(env)
    expect(status).to eq(200)
    expect(body).to eq(['hello world'])
  end

  it 'does not call the app when the request is set to be inauthentic' do
    described_class.authentic = false
    mw = described_class.new(@rack_app)
    env = {'REQUEST_METHOD' => 'GET', 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar'}
    status, headers, body = mw.call(env)
    expect(@rack_app).not_to receive(:call)
  end

  it 'returns appropriate responses when the request is set to be inauthentic' do
    described_class.authentic = false
    mw = described_class.new(@rack_app)
    env = {'REQUEST_METHOD' => 'GET', 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar'}
    status, headers, body = mw.call(env)
    expect(status).to eq(401)
  end

  it 'after an inauthentic request, the next request is authentic by default' do
    described_class.authentic = false
    mw = described_class.new(@rack_app)
    env = {'REQUEST_METHOD' => 'GET', 'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar'}
    status, headers, body = mw.call(env)
    expect(status).to eq(401)
    status, headers, body = mw.call(env)
    expect(status).to eq(200)
  end
end

describe MAuth::Rack::ResponseSigner do
  include_examples MAuth::Middleware
end
describe MAuth::Faraday::ResponseAuthenticator do
  include_examples MAuth::Middleware
  before do
    @faraday_app = proc do |env|
      res = Object.new
      def res.on_complete
        yield({:status => 200, :response_headers => {'x-mws-authentication' => 'MWS foo:bar'}, :body => 'hello world'})
      end
      res
    end
  end
  it 'returns the response with env indicating authenticity when authentic' do
    mw = described_class.new(@faraday_app)
    allow(mw.mauth_client).to receive(:authenticate!)
    res = mw.call({})
    expect(200).to eq(res[:status])
    expect('foo').to eq(res['mauth.app_uuid'])
    expect(true).to eq(res['mauth.authentic'])
  end
  it 'raises InauthenticError on inauthentic response' do
    mw = described_class.new(@faraday_app)
    allow(mw.mauth_client).to receive(:authenticate!).and_raise(MAuth::InauthenticError.new)
    expect{res = mw.call({})}.to raise_error(MAuth::InauthenticError)
  end
  it 'raises UnableToAuthenticateError when unable to authenticate' do
    mw = described_class.new(@faraday_app)
    allow(mw.mauth_client).to receive(:authenticate!).and_raise(MAuth::UnableToAuthenticateError.new)
    expect{res = mw.call({})}.to raise_error(MAuth::UnableToAuthenticateError)
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
  class FakeApp
    def call(env)
    end
  end
  let(:agent_base) { 'Sallust' }
  let(:app) { FakeApp.new }
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
