require File.dirname(__FILE__) + '/spec_helper'
require 'mauth/client'
require 'logger'

describe MAuth::Client do
  describe '.default_config' do
    def with_env(tmp_env)
      begin
        orig_env = ENV.to_hash.dup
        ENV.update(tmp_env)
        yield
      ensure
        ENV.replace(orig_env)
      end
    end

    def with_rails(rails_stuff)
      require 'ostruct'
      begin
        Object.const_set(:Rails, OpenStruct.new(rails_stuff))
        yield
      ensure
        Object.send(:remove_const, :Rails)
      end
    end

    it 'guesses everything' do
      Dir.chdir('spec/config_root') do
        expect(MAuth::Client.default_config['app_uuid']).to eq('NORMAL-DEVELOPMENT')
      end
    end

    it 'raises when it cannot find mauth config yml' do
      expect { MAuth::Client.default_config(:mauth_config_yml => "no_file_here") }.to raise_error(MAuth::Client::ConfigurationError)
    end

    it 'has root option specified' do
      expect(MAuth::Client.default_config(:root => 'spec/config_root')['app_uuid']).to eq('NORMAL-DEVELOPMENT')
    end

    it 'has root env variable specified' do
      %w(RAILS_ROOT RACK_ROOT APP_ROOT).each do |var|
        with_env(var => 'spec/config_root') do
          expect(MAuth::Client.default_config['app_uuid']).to eq('NORMAL-DEVELOPMENT')
        end
      end
    end

    it 'has environment option specified' do
      Dir.chdir('spec/config_root') do
        expect(MAuth::Client.default_config(:environment => 'production')['app_uuid']).to eq('NORMAL-PRODUCTION')
      end
    end

    it 'has environment env variable specified' do
      Dir.chdir('spec/config_root') do
        %w(RAILS_ENV RACK_ENV).each do |var|
          with_env(var => 'production') do
            expect(MAuth::Client.default_config['app_uuid']).to eq('NORMAL-PRODUCTION')
          end
        end
      end
    end

    it 'has Rails.environment specified' do
      Dir.chdir('spec/config_root') do
        with_rails(:environment => 'production') do
          expect(MAuth::Client.default_config['app_uuid']).to eq('NORMAL-PRODUCTION')
        end
      end
    end

    it 'has mauth_config_yml option specified' do
      expect(MAuth::Client.default_config(:mauth_config_yml => 'spec/config_root/config/mauth.yml')['app_uuid']).to eq('NORMAL-DEVELOPMENT')
    end

    it 'has MAUTH_CONFIG_YML env var specified' do
      with_env('MAUTH_CONFIG_YML' => 'spec/config_root/config/mauth.yml') do
        expect(MAuth::Client.default_config['app_uuid']).to eq('NORMAL-DEVELOPMENT')
      end
    end

    it 'has logger option specified' do
      Dir.chdir('spec/config_root') do
        logger = ::Logger.new(StringIO.new)
        expect(MAuth::Client.default_config(:logger => logger)['logger']).to eq(logger)
      end
    end

    it 'has Rails.logger specified' do
      Dir.chdir('spec/config_root') do
        logger = ::Logger.new(StringIO.new)
        with_rails(:logger => logger) do
          expect(MAuth::Client.default_config['logger']).to eq(logger)
        end
      end
    end
  end
end
