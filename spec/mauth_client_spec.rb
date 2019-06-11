require 'spec_helper'
require 'faraday'
require 'mauth/client'
require 'securerandom'
require_relative './support/shared_contexts/client_context'

describe MAuth::Client do
  include_context 'client'

  describe '#initialize' do
    it 'initializes without config' do
      mc = MAuth::Client.new
    end

    require 'logger'
    config_pieces = {
      logger: ::Logger.new(STDERR),
      mauth_baseurl: 'https://mauth.imedidata.net',
      mauth_api_version: 'v1',
    }
    config_pieces.each do |config_key, value|
      it "initializes with #{config_key}" do
        # set with a string
        mc = MAuth::Client.new(config_key.to_s => value)
        # check the accessor method
        expect(value).to eq(mc.send(config_key))
        # set with a symbol
        mc = MAuth::Client.new(config_key.to_s => value)
        # check the accossor method
        expect(value).to eq(mc.send(config_key))
      end
    end

    it 'logs to Rails.logger if it can' do
      Object.const_set('Rails', Object.new)
      def (::Rails).logger
        @logger ||= Logger.new(STDERR)
      end
      expect(::Rails.logger).to eq(MAuth::Client.new.logger)
      Object.send(:remove_const, 'Rails')
    end

    it 'builds a logger if Rails is defined, but Rails.logger is nil' do
      Object.const_set('Rails', Object.new)
      def (::Rails).logger
        nil
      end
      logger = double('logger')
      allow(::Logger).to receive(:new).with(anything).and_return(logger)
      expect(logger).to eq(MAuth::Client.new.logger)
      Object.send(:remove_const, 'Rails')
    end

    it 'initializes with app_uuid' do
      uuid = "40e19273-6a43-41d1-ba71-71cbb1b69d35"
      [{ app_uuid: uuid }, { 'app_uuid' => uuid }].each do |config|
        mc = MAuth::Client.new(config)
        expect(uuid).to eq(mc.client_app_uuid)
      end
    end

    it 'initializes with ssl_cert_path' do
      ssl_certs_path = 'ssl/certs/path'
      [{ ssl_certs_path: ssl_certs_path }, { 'ssl_certs_path' => ssl_certs_path }].each do |config|
        mc = MAuth::Client.new(config)
        expect(ssl_certs_path).to eq(mc.ssl_certs_path)
      end
    end

    it 'initializes with private key' do
      key = OpenSSL::PKey::RSA.generate(2048)
      [{ private_key: key }, { 'private_key' => key }, { private_key: key.to_s }, { 'private_key' => key.to_s }].each do |config|
        mc = MAuth::Client.new(config)
        # can't directly compare the OpenSSL::PKey::RSA instances
        expect(key.class).to eq(mc.private_key.class)
        expect(key.to_s).to eq(mc.private_key.to_s)
      end
    end

    it 'correctly initializes with authenticate_with_only_v2 as true with boolean true or string "true"' do
      [true, 'true'].each do |authenticate_with_only_v2|
        [{ authenticate_with_only_v2: authenticate_with_only_v2 }, { 'authenticate_with_only_v2' => authenticate_with_only_v2 }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.authenticate_with_only_v2?).to eq(true)
        end
      end
    end

    it 'correctly initializes with authenticate_with_only_v2 as false with any other values' do
      ['tru', false, 'false', 1, 0, nil, ''].each do |authenticate_with_only_v2|
        [{ authenticate_with_only_v2: authenticate_with_only_v2 }, { 'authenticate_with_only_v2' => authenticate_with_only_v2 }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.authenticate_with_only_v2?).to eq(false)
        end
      end
    end

    it 'correctly initializes with sign_requests_with_only_v2 as true with boolean true or string "true"' do
      [true, 'true'].each do |sign_requests_with_only_v2|
        [{ sign_requests_with_only_v2: sign_requests_with_only_v2 }, { 'sign_requests_with_only_v2' => sign_requests_with_only_v2 }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.sign_requests_with_only_v2?).to eq(true)
        end
      end
    end

    it 'correctly initializes with sign_requests_with_only_v2 as false with any other values' do
      ['tru', false, 'false', 1, 0, nil].each do |sign_requests_with_only_v2|
        [{ sign_requests_with_only_v2: sign_requests_with_only_v2 }, { 'sign_requests_with_only_v2' => sign_requests_with_only_v2 }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.sign_requests_with_only_v2?).to eq(false)
        end
      end
    end
  end

  require 'mauth/request_and_response'
  class TestSignableRequest < MAuth::Request
    include MAuth::Signed
    attr_accessor :headers

    def merge_headers(headers)
      self.class.new(@attributes_for_signing).tap{ |r| r.headers = (@headers || {}).merge(headers) }
    end

    def x_mws_time
      headers['X-MWS-Time']
    end

    def x_mws_authentication
      headers['X-MWS-Authentication']
    end

    def mcc_authentication
      headers['MCC-Authentication']
    end

    def mcc_time
      headers['MCC-Time']
    end
  end

  describe '#signed' do
    it 'adds only X-MWS-Time and X-MWS-Authentication headers when signing with v1 override' do
      expect(v1_signed_req.headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time')
      expect(v1_signed_req.headers.keys).not_to include('MCC-Authentication', 'MCC-Time')
    end

    it 'adds only MCC-Time and MCC-Authentication headers when signing with v2 override' do
      expect(v2_signed_req.headers.keys).to include('MCC-Authentication', 'MCC-Time')
      expect(v2_signed_req.headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
    end

    context 'when the sign_requests_with_only_v2 flag is true' do
      let(:sign_requests_with_only_v2) { true }

      it 'adds only MCC-Time and MCC-Authentication headers when signing' do
        signed_request = client.signed(request)
        expect(signed_request.headers.keys).to include('MCC-Authentication', 'MCC-Time')
        expect(signed_request.headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
      end
    end

    it 'by default adds X-MWS-Time, X-MWS-Authentication, MCC-Time, MCC-Authentication headers when signing' do
      signed_request = client.signed(request)
      expect(signed_request.headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time','MCC-Authentication', 'MCC-Time')
    end

    it "can't sign without a private key" do
      mc = MAuth::Client.new(app_uuid: app_uuid)
      expect { mc.signed(request) }.to raise_error(MAuth::UnableToSignError)
    end

    it "can't sign without an app uuid" do
      mc = MAuth::Client.new(private_key: OpenSSL::PKey::RSA.generate(2048))
      expect { mc.signed(request) }.to raise_error(MAuth::UnableToSignError)
    end
  end

  describe '#signed_headers' do
    it 'returns only X-MWS-Time and X-MWS-Authentication headers when called with v1 override' do
      signed_headers = client.signed_headers(request, v1_only_override: true)
      expect(signed_headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time')
      expect(signed_headers.keys).not_to include('MCC-Authentication', 'MCC-Time')
    end

    it 'returns only MCC-Time and MCC-Authentication headers when called with v2 override' do
      signed_headers = client.signed_headers(request, v2_only_override: true)
      expect(signed_headers.keys).to include('MCC-Authentication', 'MCC-Time')
      expect(signed_headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
    end

    context 'when the sign_requests_with_only_v2 flag is true' do
      let(:sign_requests_with_only_v2) { true }

      it 'returns only MCC-Time and MCC-Authentication headers when signing' do
        signed_headers = client.signed_headers(request)
        expect(signed_headers.keys).to include('MCC-Authentication', 'MCC-Time')
        expect(signed_headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
      end
    end

    it 'by default returns X-MWS-Time, X-MWS-Authentication, MCC-Time, MCC-Authentication headers' do
      signed_headers = client.signed_headers(request)
      expect(signed_headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time', 'MCC-Authentication', 'MCC-Time')
    end
  end
end
