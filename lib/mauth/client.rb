# frozen_string_literal: true

require 'uri'
require 'openssl'
require 'base64'
require 'json'
require 'yaml'
require 'mauth/core_ext'
require 'mauth/autoload'
require 'mauth/version'
require 'mauth/client/authenticator'
require 'mauth/client/signer'
require 'mauth/config_env'
require 'mauth/errors'
require 'mauth/private_key_helper'

module MAuth
  # does operations which require a private key and corresponding app uuid. this is primarily:
  # - signing outgoing requests and responses
  # - authenticating incoming requests and responses, which may require retrieving the appropriate
  #   public key from mAuth (which requires a request to mAuth which is signed using the private
  #   key)
  #
  # this nominally operates on request and response objects, but really the only requirements are
  # that the object responds to the methods of MAuth::Signable and/or MAuth::Signed (as
  # appropriate)
  class Client
    MWS_TOKEN = 'MWS'
    MWSV2_TOKEN = 'MWSV2'
    AUTH_HEADER_DELIMITER = ';'
    RACK_ENV_APP_UUID_KEY = 'mauth.app_uuid'

    include Authenticator
    include Signer

    # returns a configuration (to be passed to MAuth::Client.new) which is configured from information stored in
    # standard places. all of which is overridable by options in case some defaults do not apply.
    #
    # options (may be symbols or strings) - any or all may be omitted where your usage conforms to the defaults.
    # - mauth_config - MAuth configuration. defaults to load this from environment variables. if this is specified,
    #   no environment variable is loaded, and the given config is passed through with any other defaults applied.
    #   at the moment, the only other default is to set the logger.
    # - logger - by default checks ::Rails.logger
    def self.default_config(options = {})
      options = options.stringify_symbol_keys

      # find mauth config
      mauth_config = options['mauth_config'] || ConfigEnv.load

      unless mauth_config.key?('logger')
        # the logger. Rails.logger if it exists, otherwise, no logger
        mauth_config['logger'] = options['logger'] || begin
          if Object.const_defined?(:Rails) && ::Rails.respond_to?(:logger)
            Rails.logger
          end
        end
      end

      mauth_config
    end

    # new client with the given App UUID and public key. config may include the following (all
    # config keys may be strings or symbols):
    # - private_key - required for signing and for authentication.
    #   may be given as a string or a OpenSSL::PKey::RSA instance.
    # - app_uuid - required in the same circumstances where a private_key is required
    # - mauth_baseurl - required. needed to retrieve public keys.
    # - mauth_api_version - required. only 'v1' exists / is supported as of this writing.
    # - logger - a Logger to which any useful information will be written. if this is omitted and
    #   Rails.logger exists, that will be used.
    def initialize(config = {})
      # stringify symbol keys
      given_config = config.stringify_symbol_keys
      # build a configuration which discards any irrelevant parts of the given config (small memory usage matters here)
      @config = {}
      if given_config['private_key_file'] && !given_config['private_key']
        given_config['private_key'] = File.read(given_config['private_key_file'])
      end
      @config['private_key'] =
        case given_config['private_key']
        when nil
          nil
        when String
          PrivateKeyHelper.load(given_config['private_key'])
        when OpenSSL::PKey::RSA
          given_config['private_key']
        else
          raise MAuth::Client::ConfigurationError,
            "unrecognized value given for 'private_key' - this may be a " \
            "String, a OpenSSL::PKey::RSA, or omitted; instead got: #{given_config['private_key'].inspect}"
        end
      @config['app_uuid'] = given_config['app_uuid']
      @config['mauth_baseurl'] = given_config['mauth_baseurl']
      @config['mauth_api_version'] = given_config['mauth_api_version']
      @config['logger'] = given_config['logger'] || begin
        if Object.const_defined?(:Rails) && Rails.logger
          Rails.logger
        else
          require 'logger'
          ::Logger.new(File.open(File::NULL, File::WRONLY))
        end
      end

      request_config = { timeout: 10, open_timeout: 3 }
      request_config.merge!(symbolize_keys(given_config['faraday_options'])) if given_config['faraday_options']
      @config['faraday_options'] = { request: request_config } || {}
      @config['ssl_certs_path'] = given_config['ssl_certs_path'] if given_config['ssl_certs_path']
      @config['v2_only_authenticate'] = given_config['v2_only_authenticate'].to_s.casecmp('true').zero?
      @config['v2_only_sign_requests'] = given_config['v2_only_sign_requests'].to_s.casecmp('true').zero?
      @config['v1_only_sign_requests'] = given_config['v1_only_sign_requests'].to_s.casecmp('true').zero?
      if @config['v2_only_sign_requests'] && @config['v1_only_sign_requests']
        raise MAuth::Client::ConfigurationError, 'v2_only_sign_requests and v1_only_sign_requests may not both be true'
      end

      @config['disable_fallback_to_v1_on_v2_failure'] =
        given_config['disable_fallback_to_v1_on_v2_failure'].to_s.casecmp('true').zero?
      @config['use_rails_cache'] = given_config['use_rails_cache']
    end

    def logger
      @config['logger']
    end

    def client_app_uuid
      @config['app_uuid']
    end

    def mauth_baseurl
      @config['mauth_baseurl'] || raise(MAuth::Client::ConfigurationError, 'no configured mauth_baseurl!')
    end

    def mauth_api_version
      @config['mauth_api_version'] || raise(MAuth::Client::ConfigurationError, 'no configured mauth_api_version!')
    end

    def private_key
      @config['private_key']
    end

    def faraday_options
      @config['faraday_options']
    end

    def ssl_certs_path
      @config['ssl_certs_path']
    end

    def v2_only_sign_requests?
      @config['v2_only_sign_requests']
    end

    def v2_only_authenticate?
      @config['v2_only_authenticate']
    end

    def disable_fallback_to_v1_on_v2_failure?
      @config['disable_fallback_to_v1_on_v2_failure']
    end

    def v1_only_sign_requests?
      @config['v1_only_sign_requests']
    end

    def assert_private_key(err)
      raise err unless private_key
    end

    def cache_store
      Rails.cache if @config['use_rails_cache'] && Object.const_defined?(:Rails) && ::Rails.respond_to?(:cache)
    end

    private

    def mauth_service_response_error(response)
      message = "mAuth service responded with #{response.status}: #{response.body}"
      logger.error(message)
      error = UnableToAuthenticateError.new(message)
      error.mauth_service_response = response
      raise error
    end

    # Changes all keys in the top level of the hash to symbols.  Does not affect nested hashes inside this one.
    def symbolize_keys(hash)
      hash.keys.each do |key|
        hash[(key.to_sym rescue key) || key] = hash.delete(key)
      end
      hash
    end
  end
end
