require 'spec_helper'
require 'mauth/client'
require 'mauth/security_token_cacher'

describe MAuth::Client::LocalAuthenticator::SecurityTokenCacher do
  describe '#signed_mauth_connection' do
    it 'properly sets the timeouts on the faraday connection' do
      config = {
        'private_key' => OpenSSL::PKey::RSA.generate(2048),
        'faraday_options' => { 'timeout' => '23', 'open_timeout' => '18' },
        'mauth_baseurl' => 'https://mauth.imedidata.net'
      }
      mc = MAuth::Client.new(config)
      connection = MAuth::Client::LocalAuthenticator::SecurityTokenCacher.new(mc).send(:signed_mauth_connection)
      expect(connection.options[:timeout]).to eq('23')
      expect(connection.options[:open_timeout]).to eq('18')
    end
  end
end
