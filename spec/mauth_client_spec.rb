require File.dirname(__FILE__) + '/spec_helper'
require 'mauth/client'

describe MAuth::Client do
  describe '#initialize' do
    it 'initializes without config' do
      mc = MAuth::Client.new
    end

    require 'logger'
    config_pieces = {
      :logger => ::Logger.new(STDERR),
      :mauth_baseurl => 'https://mauth.imedidata.net',
      :mauth_api_version => 'v1',
    }
    config_pieces.each do |config_key, value|
      it "initializes with #{config_key}" do
        # set with a string
        mc = MAuth::Client.new(config_key.to_s => value)
        # check the accessor method
        assert_equal value, mc.send(config_key)
        # set with a symbol 
        mc = MAuth::Client.new(config_key.to_s => value)
        # check the accossor method 
        assert_equal value, mc.send(config_key)
      end
    end

    it 'logs to Rails.logger if it can' do
      Object.const_set('Rails', Object.new)
      def (::Rails).logger
        @logger ||= Logger.new(STDERR)
      end
      assert_equal ::Rails.logger, MAuth::Client.new.logger
      Object.send(:remove_const, 'Rails')
    end

    it 'initializes with app_uuid' do
      uuid = "40e19273-6a43-41d1-ba71-71cbb1b69d35"
      [{:app_uuid => uuid}, {'app_uuid' => uuid}].each do |config|
        mc = MAuth::Client.new(config)
        assert_equal uuid, mc.client_app_uuid
      end
    end

    it 'initializes with private key' do
      key = OpenSSL::PKey::RSA.generate(2048)
      [{:private_key => key}, {'private_key' => key}, {:private_key => key.to_s}, {'private_key' => key.to_s}].each do |config|
        mc = MAuth::Client.new(config)
        # can't directly compare the OpenSSL::PKey::RSA instances 
        assert_equal key.class, mc.private_key.class
        assert_equal key.to_s, mc.private_key.to_s
      end
    end
  end

  require 'mauth/request_and_response'
  class TestSignableRequest < MAuth::Request
    attr_accessor :headers
    def merge_headers(headers)
      self.class.new(@attributes_for_signing).tap{|r| r.headers = (@headers || {}).merge(headers) }
    end
  end

  describe '#signed' do
    before { @request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom') }
    it 'adds X-MWS-Time and X-MWS-Authentication headers when signing' do
      mc = MAuth::Client.new(:private_key => OpenSSL::PKey::RSA.generate(2048), :app_uuid => UUIDTools::UUID.random_create.to_s)
      signed_request = mc.signed(@request)
      assert signed_request.headers.keys.include?('X-MWS-Authentication')
      assert signed_request.headers.keys.include?('X-MWS-Time')
    end
    it "can't sign without a private key" do
      mc = MAuth::Client.new(:app_uuid => UUIDTools::UUID.random_create.to_s)
      assert_raises(MAuth::UnableToSignError) { mc.signed(@request) }
    end
    it "can't sign without an app uuid" do
      mc = MAuth::Client.new(:private_key => OpenSSL::PKey::RSA.generate(2048))
      assert_raises(MAuth::UnableToSignError) { mc.signed(@request) }
    end
  end
  describe '#signed_headers' do
    it 'returns a hash with X-MWS-Time and X-MWS-Authentication headers' do
      mc = MAuth::Client.new(:private_key => OpenSSL::PKey::RSA.generate(2048), :app_uuid => UUIDTools::UUID.random_create.to_s)
      signed_headers = mc.signed_headers(TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom'))
      assert signed_headers.keys.include?('X-MWS-Authentication')
      assert signed_headers.keys.include?('X-MWS-Time')
    end
  end
end
