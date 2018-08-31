require 'spec_helper'
require 'mauth/proxy'
require 'faraday'

describe MAuth::Proxy do
  class FakeResponse
    attr_accessor :headers, :status, :body

    def initialize
      @headers = {}
      @status = 200
    end
  end
  class FakeConnection
    attr_accessor :headers
    def run_request(request_method, request_fullpath, request_body, request_headers)
      @headers = request_headers
      return FakeResponse.new
    end
  end

  describe '#initialize' do
    let(:url) {"http://test-url-not-here.no"}
    let(:env) {Rack::MockRequest.env_for(url, {})}

    it 'makes requests with custom header' do
      double = FakeConnection.new
      allow(Faraday).to receive(:new).and_return(double)
      mp = MAuth::Proxy.new(url, :headers => ["Content-type: text/jordi"])
      mp.call(env)
      expect(double.headers["Content-type"]).to eq("text/jordi")
    end

    it 'makes requests with multiple custom header' do
      double = FakeConnection.new
      allow(Faraday).to receive(:new).and_return(double)
      mp = MAuth::Proxy.new(url, :headers => ["Content-type: text/jordi", "Accepts : text/jordi"])
      mp.call(env)
      expect(double.headers["Content-type"]).to eq("text/jordi")
      expect(double.headers["Accepts"]).to eq("text/jordi")
    end

    it 'raises an error if the header format is wrong' do
      double = FakeConnection.new
      allow(Faraday).to receive(:new).and_return(double)
      expect{MAuth::Proxy.new(url, :headers => ["Content-type= text/jordi"])
      }.to raise_error("Headers must be in the format of [key]:[value]")
    end

    it 'supports multiple :' do
      double = FakeConnection.new
      allow(Faraday).to receive(:new).and_return(double)
      mp = MAuth::Proxy.new(url, :headers => ["Expiry-time: 3/6/1981 12:01.00"])
      mp.call(env)
      expect(double.headers["Expiry-time"]).to eq("3/6/1981 12:01.00")
    end

    it 'forwards headers that begin with HTTP_ except for HTTP_HOST and removes the HTTP_ prefix' do
      double = FakeConnection.new
      allow(Faraday).to receive(:new).and_return(double)
      mp = MAuth::Proxy.new(url)
      http_headers = { 'HTTP_FOO' => 'bar_value', 'HTTP_HOST' => 'my_host', 'HTTP_BIZ' => 'buzz_value' }
      mp.call(Rack::MockRequest.env_for(url, http_headers))
      expect(double.headers['FOO']).to eq('bar_value')
      expect(double.headers['BIZ']).to eq('buzz_value')
      expect(double.headers.keys).to_not include('HTTP_HOST')
      expect(double.headers.keys).to_not include('HOST')
      expect(double.headers.keys).to_not include('HTTP_FOO')
      expect(double.headers.keys).to_not include('HTTP_BIZ')
    end

  end
end
