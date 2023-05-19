# frozen_string_literal: true

require 'spec_helper'
require 'mauth/client'

describe MAuth::Client do
  describe '.default_config' do
    let(:logger) { double }

    def with_rails(rails_stuff)
      require 'ostruct'
      begin
        Object.const_set(:Rails, Struct.new(*rails_stuff.keys).new(*rails_stuff.values))
        yield
      ensure
        Object.send(:remove_const, :Rails)
      end
    end

    it 'guesses everything' do
      expect(MAuth::Client.default_config['app_uuid']).to eq('fb17460e-9868-11e1-8399-0090f5ccb4d3')
    end

    it 'has logger option specified' do
      expect(MAuth::Client.default_config(logger: logger)['logger']).to eq(logger)
    end

    it 'has Rails.logger specified' do
      logger = Logger.new(StringIO.new)
      with_rails(logger: logger) do
        expect(MAuth::Client.default_config['logger']).to eq(logger)
      end
    end
  end
end
