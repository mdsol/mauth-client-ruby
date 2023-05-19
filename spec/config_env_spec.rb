# frozen_string_literal: true

require 'spec_helper'
require 'mauth/client'

describe MAuth::ConfigEnv do
  describe '.load' do
    let(:config) { described_class.load }

    before do
      allow(ENV).to receive(:fetch).and_call_original
      MAuth::ConfigEnv.instance_variable_set(:@env, nil)
    end

    context 'configured by env vars' do
      before do
        allow(ENV).to receive(:fetch).with('MAUTH_URL', anything).and_return('https://mauth.com')
        allow(ENV).to receive(:fetch).with('MAUTH_API_VERSION', anything).and_return('v123')
        allow(ENV)
          .to receive(:fetch).with('MAUTH_APP_UUID', anything).and_return('9d10623d-7ee6-4088-91cf-fe2c660a98bc')
        allow(ENV).to receive(:fetch).with('MAUTH_PRIVATE_KEY', anything).and_return('configured key')
        allow(ENV).to receive(:fetch).with('MAUTH_V2_ONLY_AUTHENTICATE', anything).and_return('true')
        allow(ENV).to receive(:fetch).with('MAUTH_V2_ONLY_SIGN_REQUESTS', anything).and_return('true')
        allow(ENV).to receive(:fetch).with('MAUTH_DISABLE_FALLBACK_TO_V1_ON_V2_FAILURE', anything).and_return('true')
        allow(ENV).to receive(:fetch).with('MAUTH_V1_ONLY_SIGN_REQUESTS', anything).and_return('false')
      end

      it 'returns the processed config' do
        expect(config['mauth_baseurl']).to eq('https://mauth.com')
        expect(config['mauth_api_version']).to eq('v123')
        expect(config['app_uuid']).to eq('9d10623d-7ee6-4088-91cf-fe2c660a98bc')
        expect(config['private_key']).to eq('configured key')
        expect(config['v2_only_authenticate']).to be true
        expect(config['v2_only_sign_requests']).to be true
        expect(config['disable_fallback_to_v1_on_v2_failure']).to be true
        expect(config['v1_only_sign_requests']).to be false
      end
    end

    context 'configured by defaults' do
      before { allow(OpenSSL::PKey::RSA).to receive(:generate).with(2048).and_return('generated key') }

      it 'returns the processed config' do
        expect(config['mauth_baseurl']).to eq('http://localhost:7000')
        expect(config['mauth_api_version']).to eq('v1')
        expect(config['app_uuid']).to eq('fb17460e-9868-11e1-8399-0090f5ccb4d3')
        expect(config['private_key']).to eq('generated key')
        expect(config['v2_only_authenticate']).to be false
        expect(config['v2_only_sign_requests']).to be false
        expect(config['disable_fallback_to_v1_on_v2_failure']).to be false
        expect(config['v1_only_sign_requests']).to be true
      end
    end

    context 'running in production' do
      before { allow(ENV).to receive(:fetch).with('RAILS_ENV').and_return('production') }

      %w[MAUTH_URL MAUTH_APP_UUID MAUTH_PRIVATE_KEY].each do |env_var|
        it "requires the presence of the #{env_var} variable" do
          expect { config }.to raise_error(/#{env_var} environment variable must be set/)
        end
      end
    end
  end
end
