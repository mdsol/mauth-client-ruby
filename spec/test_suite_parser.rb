# frozen_string_literal: true

# file to handle loading and parsing of mauth protocol test suite cases in order
# to run them as rpsec tests

require 'mauth/client'
require 'faraday'

module ProtocolHelper
  TEST_SUITE_SUBMODULE_PATH = 'spec/fixtures/mauth-protocol-test-suite'
  CASE_PATH = "#{TEST_SUITE_SUBMODULE_PATH}/protocols/MWSV2"

  class Config
    class << self

      attr_reader :request_time, :app_uuid, :mauth_client, :pub_key

      def load
        config_hash = JSON.parse(File.read("#{TEST_SUITE_SUBMODULE_PATH}/signing-config.json"))
        @request_time = config_hash["request_time"]
        @app_uuid = config_hash["app_uuid"]
        @mauth_client = Mauth::Client.new(
          app_uuid: @app_uuid,
          private_key_file: File.join(TEST_SUITE_SUBMODULE_PATH, config_hash["private_key_file"])
        )
        @pub_key = File.read("#{TEST_SUITE_SUBMODULE_PATH}/signing-params/rsa-key-pub")
      end

      def cases
        # Dir.children(CASE_PATH) only added in ruby 2.5.0 and we support 2.3.
        Dir.entries(CASE_PATH) - %w[. ..]
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

  # utility to help write new cases
  class CaseWriter
    def initialize(case_name)
      ProtocolHelper::Config.load
      @case_name = case_name
    end

    def build_case(attrs)
      @req_attrs = attrs
      Dir.mkdir("#{CASE_PATH}/#{case_name}")
      write_req
      write_sts
      write_sig
      write_authz
    end

    def build_case_from_sts
      write_sig(File.read(file_by_ext('sts')))
    end

    private

    attr_reader :case_name, :req_attrs

    def write_req
      write_file('req', JSON.pretty_generate(req_attrs))
    end

    def req
      faraday_env = {
        method: req_attrs['verb'],
        url: URI(req_attrs['url']),
        body: req_attrs['body']
      }

      req = Mauth::Faraday::Request.new(faraday_env)
    end

    def sts
      signing_info = {
        app_uuid: ProtocolHelper::Config.app_uuid,
        time: ProtocolHelper::Config.request_time
      }
      sts = req.string_to_sign_v2(signing_info)
    end

    def write_sts
      write_file('sts', sts)
    end

    def sig(given_sts)
      mc = ProtocolHelper::Config.mauth_client
      mc.signature_v2(given_sts || sts)
    end

    def write_sig(given_sts = nil)
      write_file('sig', sig(given_sts))
    end

    def auth_headers
      mc = ProtocolHelper::Config.mauth_client
      mc.signed_headers_v2(req, time: ProtocolHelper::Config.request_time)
    end

    def write_authz
      write_file('authz', JSON.pretty_generate(auth_headers))
    end

    def write_file(ext, contents)
      File.write("#{CASE_PATH}/#{case_name}/#{case_name}.#{ext}", contents)
    end

    def file_by_ext(ext)
      Dir.glob("#{CASE_PATH}/#{case_name}/*#{ext}").first
    end
  end
end
