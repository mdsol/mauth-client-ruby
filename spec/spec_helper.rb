require 'timecop'
require 'json'
require 'rack/mock'
require 'byebug'
require 'webmock/rspec'

require 'simplecov'
SimpleCov.start

MAUTH_CONFIG_YML = File.expand_path('../config_root/config/mauth.yml', __FILE__).freeze

RSpec.configure do |config|
  config.before do
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('MAUTH_CONFIG_YML').and_return(MAUTH_CONFIG_YML)
  end
end
