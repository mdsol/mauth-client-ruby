require 'mauth/client'
require 'faraday'

# file to handle loading and parsing of mauth protocol test suite cases in order
# to run them as rpsec tests

module ProtocolHelper
  TEST_SUITE_BASE_PATH = 'spec/fixtures/mauth-protocol-test-suite'.freeze
  CASE_PATH = "#{TEST_SUITE_BASE_PATH}/protocols/MWSV2".freeze

  class Config
    class << self

      attr_reader :request_time, :app_uuid, :mauth_client, :pub_key

      def load
        config_hash = JSON.parse(File.read("#{TEST_SUITE_BASE_PATH}/signing-config.json"))
        @request_time = config_hash["request_time"]
        @app_uuid = config_hash["app_uuid"]
        @mauth_client = MAuth::Client.new(
          app_uuid: @app_uuid,
          private_key_file: File.join(TEST_SUITE_BASE_PATH, config_hash["private_key_file"])
        )
        @pub_key = File.read("#{TEST_SUITE_BASE_PATH}/signing-params/rsa-key-pub")
      end

      def cases
        Dir.children("#{CASE_PATH}")
      end
    end
  end

  class CaseParser
    def initialize(case_name)
      @case_name = case_name
    end

    def req_attrs
      @req_attrs ||= begin
        JSON.parse(File.read(file_by_ext('req'))).tap do |attrs|
          if attrs.has_key?('body_filepath')
            attrs['body'] = File.read("#{CASE_PATH}/#{case_name}/#{attrs['body_filepath']}")
          end
        end
      end
    end

    def sts
      File.read(file_by_ext('sts'))
    end

    def sig
      File.read(file_by_ext('sig'))
    end

    def auth_headers
      JSON.parse(File.read(file_by_ext('authz')))
    end

    private

    attr_reader :case_name

    def file_by_ext(ext)
      Dir.glob("#{CASE_PATH}/#{case_name}/*#{ext}").first
    end
  end
end
