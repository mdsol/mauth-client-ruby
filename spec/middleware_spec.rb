require File.dirname(__FILE__) + '/spec_helper'
require 'mauth/rack'
require 'mauth/faraday'

shared_examples MAuth::Middleware do
  it 'uses a given mauth_client if given' do
    mauth_client = mock
    assert_equal mauth_client, described_class.new(mock('app'), :mauth_client => mauth_client).mauth_client
    assert_equal mauth_client, described_class.new(mock('app'), 'mauth_client' => mauth_client).mauth_client
  end
  it 'builds a mauth client if not given a mauth_client' do
    mauth_config = {:mauth_baseurl => 'http://mauth', :mauth_api_version => 'v1'}
    middleware_instance = described_class.new(mock('app'), mauth_config)
    assert_equal mauth_config[:mauth_baseurl], middleware_instance.mauth_client.mauth_baseurl
    assert_equal mauth_config[:mauth_api_version], middleware_instance.mauth_client.mauth_api_version
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
    env = mock
    mw.mauth_client.should_not_receive(:authentic?)
    @rack_app.should_receive(:call).with(env).and_return(@res)
    status, headers, body = mw.call(env)
    assert_equal 200, status
    assert_equal ['hello world'], body
  end
  it 'authenticates if should_authenticate_check is omitted or indicates to' do
    [nil, proc {|env| true }].each do |should_authenticate_check|
      mw = described_class.new(@rack_app, :should_authenticate_check => should_authenticate_check)
      env = {'HTTP_X_MWS_AUTHENTICATION' => 'MWS foo:bar'}
      mw.mauth_client.should_receive(:authentic?).and_return(true)
      @rack_app.should_receive(:call).with(env.merge('mauth.app_uuid' => 'foo', 'mauth.authentic' => true)).and_return(@res)
      status, headers, body = mw.call(env)
      assert_equal 200, status
      assert_equal ['hello world'], body
    end
  end
  it 'returns 401 and does not call the app if authentication fails' do
    mw = described_class.new(@rack_app)
    mw.mauth_client.should_receive(:authentic?).and_return(false)
    @rack_app.should_not_receive(:call)
    status, headers, body = mw.call(mock('env'))
    assert_equal 401, status
    assert_equal ['Unauthorized'], body
  end
  it 'returns 500 and does not call the app if unable to authenticate' do
    mw = described_class.new(@rack_app)
    mw.mauth_client.should_receive(:authentic?).and_raise(MAuth::UnableToAuthenticateError.new(''))
    @rack_app.should_not_receive(:call)
    status, headers, body = mw.call(mock('env'))
    assert_equal 500, status
    assert_equal ['Could not determine request authenticity'], body
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
    mw.mauth_client.stub(:authenticate!)
    res = mw.call({})
    assert_equal 200, res[:status]
    assert_equal 'foo', res['mauth.app_uuid']
    assert_equal true, res['mauth.authentic']
  end
  it 'raises InauthenticError on inauthentic response' do
    mw = described_class.new(@faraday_app)
    mw.mauth_client.stub(:authenticate!).and_raise(MAuth::InauthenticError.new)
    assert_raises(MAuth::InauthenticError) do
      res = mw.call({})
    end
  end
  it 'raises UnableToAuthenticateError when unable to authenticate' do
    mw = described_class.new(@faraday_app)
    mw.mauth_client.stub(:authenticate!).and_raise(MAuth::UnableToAuthenticateError.new)
    assert_raises(MAuth::UnableToAuthenticateError) do
      res = mw.call({})
    end
  end
end
describe MAuth::Faraday::RequestSigner do
  include_examples MAuth::Middleware
end
