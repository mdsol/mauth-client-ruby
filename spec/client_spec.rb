# frozen_string_literal: true

require 'spec_helper'
require 'faraday'
require 'mauth/client'
require 'securerandom'
require_relative './support/shared_contexts/client'

describe MAuth::Client do
  include_context 'client'

  describe '#initialize' do
    it 'initializes without config' do
      MAuth::Client.new
    end

    require 'logger'
    config_pieces = {
      logger: ::Logger.new($stderr),
      mauth_baseurl: 'https://mauth.imedidata.net',
      mauth_api_version: 'v1'
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
      Object.const_set(:Rails, Object.new)
      def (::Rails).logger
        @logger ||= Logger.new($stderr)
      end
      expect(::Rails.logger).to eq(MAuth::Client.new.logger)
      Object.send(:remove_const, 'Rails')
    end

    it 'builds a logger if Rails is defined, but Rails.logger is nil' do
      Object.const_set(:Rails, Object.new)
      def (::Rails).logger
        nil
      end
      logger = double('logger')
      allow(::Logger).to receive(:new).with(anything).and_return(logger)
      expect(logger).to eq(MAuth::Client.new.logger)
      Object.send(:remove_const, 'Rails')
    end

    it 'initializes with app_uuid' do
      uuid = '40e19273-6a43-41d1-ba71-71cbb1b69d35'
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
      [{ private_key: key }, { 'private_key' => key }, { private_key: key.to_s },
       { 'private_key' => key.to_s }].each do |config|
        mc = MAuth::Client.new(config)
        # can't directly compare the OpenSSL::PKey::RSA instances
        expect(key.class).to eq(mc.private_key.class)
        expect(key.to_s).to eq(mc.private_key.to_s)
      end
    end

    it 'correctly initializes with v2_only_authenticate as true with boolean true or string "true"' do
      [true, 'true', 'TRUE'].each do |val|
        [{ v2_only_authenticate: val }, { 'v2_only_authenticate' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v2_only_authenticate?).to eq(true)
        end
      end
    end

    it 'correctly initializes with v2_only_authenticate as false with any other values' do
      ['tru', false, 'false', 1, 0, nil, ''].each do |val|
        [{ v2_only_authenticate: val }, { 'v2_only_authenticate' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v2_only_authenticate?).to eq(false)
        end
      end
    end

    it 'correctly initializes with v2_only_sign_requests as true with boolean true or string "true"' do
      [true, 'true', 'TRUE'].each do |val|
        [{ v2_only_sign_requests: val }, { 'v2_only_sign_requests' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v2_only_sign_requests?).to eq(true)
        end
      end
    end

    it 'correctly initializes with v2_only_sign_requests as false with any other values' do
      ['tru', false, 'false', 1, 0, nil].each do |val|
        [{ v2_only_sign_requests: val }, { 'v2_only_sign_requests' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v2_only_sign_requests?).to eq(false)
        end
      end
    end

    it 'correctly initializes with disable_fallback_to_v1_on_v2_failure as true with boolean true or string "true"' do
      [true, 'true', 'TRUE'].each do |val|
        [{ disable_fallback_to_v1_on_v2_failure: val },
         { 'disable_fallback_to_v1_on_v2_failure' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.disable_fallback_to_v1_on_v2_failure?).to eq(true)
        end
      end
    end

    it 'correctly initializes with disable_fallback_to_v1_on_v2_failure as false with any other values' do
      ['tru', false, 'false', 1, 0, nil, ''].each do |val|
        [{ disable_fallback_to_v1_on_v2_failure: val },
         { 'disable_fallback_to_v1_on_v2_failure' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.disable_fallback_to_v1_on_v2_failure?).to eq(false)
        end
      end
    end

    it 'correctly initializes with v1_only_sign_requests as true with boolean true or string "true"' do
      [true, 'true', 'TRUE'].each do |val|
        [{ v1_only_sign_requests: val }, { 'v1_only_sign_requests' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v1_only_sign_requests?).to eq(true)
        end
      end
    end

    it 'correctly initializes with v1_only_sign_requests as false with any other values' do
      ['tru', false, 'false', 1, 0, nil, ''].each do |val|
        [{ v1_only_sign_requests: val }, { 'v1_only_sign_requests' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v1_only_sign_requests?).to eq(false)
        end
      end
    end

    it 'raises an error if both v1_only_sign_requests and v2_only_sign_requests are set to true' do
      config = { v1_only_sign_requests: true, v2_only_sign_requests: true }
      expect { MAuth::Client.new(config) }.to raise_error(MAuth::Client::ConfigurationError)
    end
  end
end
