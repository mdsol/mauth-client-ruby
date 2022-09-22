# frozen_string_literal: true

require 'spec_helper'
require 'mauth/client'
require 'mauth/server_helper'

describe MAuth::ServerHelper do
  subject { described_class }
  let(:uuid) { '724d1fab-79d6-4ddf-b15b-3c1fe6bd549f' }
  let(:req_env) { Rack::MockRequest.env_for('http://frogs.world', { MAuth::Client::RACK_ENV_APP_UUID_KEY => uuid }) }
  let(:req) { Rack::Request.new(req_env) }

  let(:dummy_klass) { Class.new { extend MAuth::ServerHelper } }

  describe 'app_uuid' do
    it 'returns the authenticated app uuid from a Rack::Request object' do
      expect(dummy_klass.app_uuid(req)).to eq(uuid)
    end
  end

  describe 'app_uuid_from_env' do
    it 'returns the authenticated app uuid from an env hash' do
      expect(dummy_klass.app_uuid_from_env(req.env)).to eq(uuid)
    end
  end
end
