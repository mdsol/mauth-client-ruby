require 'uri'
require 'openssl'
require 'base64'
require 'json'
require 'yaml'
require 'mauth/core_ext'
require 'mauth/autoload'
require 'mauth/dice_bag/mauth_templates'
require 'mauth/version'
require 'mauth/authenticator_base'
require 'mauth/local_authenticator'
require 'mauth/remote_authenticator'
require 'mauth/signer'
require 'mauth/errors'

module MAuth
  class Client
    class << self
      # returns a configuration (to be passed to MAuth::Client.new) which is configured from information stored in
      # standard places. all of which is overridable by options in case some defaults do not apply.
      #
      # options (may be symbols or strings) - any or all may be omitted where your usage conforms to the defaults.
      # - root: the path relative to which this method looks for configuration yaml files. defaults to Rails.root
      #   if ::Rails is defined, otherwise ENV['RAILS_ROOT'], ENV['RACK_ROOT'], ENV['APP_ROOT'], or '.'
      # - environment: the environment, pertaining to top-level keys of the configuration yaml files. by default,
      #   tries Rails.environment, ENV['RAILS_ENV'], and ENV['RACK_ENV'], and falls back to 'development' if none
      #   of these are set.
      # - mauth_config - MAuth configuration. defaults to load this from a yaml file (see mauth_config_yml option)
      #   which is assumed to be keyed with the environment at the root. if this is specified, no yaml file is
      #   loaded, and the given config is passed through with any other defaults applied. at the moment, the only
      #   other default is to set the logger.
      # - mauth_config_yml - specifies where a mauth configuration yaml file can be found. by default checks
      #   ENV['MAUTH_CONFIG_YML'] or a file 'config/mauth.yml' relative to the root.
      # - logger - by default checks ::Rails.logger
      def default_config(options = {})
        options = options.stringify_symbol_keys

        # find the app_root (relative to which we look for yaml files). note that this
        # is different than MAuth::Client.root, the root of the mauth-client library.
        app_root = options['root'] || begin
          if Object.const_defined?('Rails') && ::Rails.respond_to?(:root) && ::Rails.root
            Rails.root
          else
            ENV['RAILS_ROOT'] || ENV['RACK_ROOT'] || ENV['APP_ROOT'] || '.'
          end
        end

        # find the environment (with which yaml files are keyed)
        env = options['environment'] || begin
          if Object.const_defined?('Rails') && ::Rails.respond_to?(:environment)
            Rails.environment
          else
            ENV['RAILS_ENV'] || ENV['RACK_ENV'] || 'development'
          end
        end

        # find mauth config, given on options, or in a file at
        # ENV['MAUTH_CONFIG_YML'] or config/mauth.yml in the app_root
        mauth_config = options['mauth_config'] || begin
          mauth_config_yml = options['mauth_config_yml']
          mauth_config_yml ||= ENV['MAUTH_CONFIG_YML']
          default_loc = 'config/mauth.yml'
          default_yml = File.join(app_root, default_loc)
          mauth_config_yml ||= default_yml if File.exist?(default_yml)
          if mauth_config_yml && File.exist?(mauth_config_yml)
            whole_config = ConfigFile.load(mauth_config_yml)
            errmessage = "#{mauth_config_yml} config has no key #{env} - it has keys #{whole_config.keys.inspect}"
            whole_config[env] || raise(MAuth::Client::ConfigurationError, errmessage)
          else
            raise MAuth::Client::ConfigurationError, "could not find mauth config yaml file. this file may be " \
              "placed in #{default_loc}, specified with the mauth_config_yml option, or specified with the " \
              "MAUTH_CONFIG_YML environment variable."
          end
        end

        unless mauth_config.key?('logger')
          # the logger. Rails.logger if it exists, otherwise, no logger
          mauth_config['logger'] = options['logger'] || begin
            if Object.const_defined?('Rails') && ::Rails.respond_to?(:logger)
              Rails.logger
            end
          end
        end

        mauth_config
      end
    end
  end

  class ConfigFile
    GITHUB_URL = 'https://github.com/mdsol/mauth-client-ruby'.freeze
    @config = {}

    def self.load(path)
      unless File.exist?(path)
        raise "File #{path} not found. Please visit #{GITHUB_URL} for details."
      end

      @config[path] ||= YAML.load_file(path)
      unless @config[path]
        raise "File #{path} does not contain proper YAML information. Visit #{GITHUB_URL} for details."
      end

      @config[path]
    end
  end
end

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
    class ConfigurationError < StandardError; end

    MWS_TOKEN = 'MWS'.freeze
    MWSV2_TOKEN = 'MWSV2'.freeze
    AUTH_HEADER_DELIMITER = ';'.freeze

    include AuthenticatorBase
    include Signer

    # new client with the given App UUID and public key. config may include the following (all
    # config keys may be strings or symbols):
    # - private_key - required for signing and for authenticating responses. may be omitted if
    #   only remote authentication of requests is being performed (with
    #   MAuth::Rack::RequestAuthenticator). may be given as a string or a OpenSSL::PKey::RSA
    #   instance.
    # - app_uuid - required in the same circumstances where a private_key is required
    # - mauth_baseurl - required. needed for local authentication to retrieve public keys; needed
    #   for remote authentication for hopefully obvious reasons.
    # - mauth_api_version - required. only 'v1' exists / is supported as of this writing.
    # - logger - a Logger to which any useful information will be written. if this is omitted and
    #   Rails.logger exists, that will be used.
    # - authenticator - this pretty much never needs to be specified. LocalAuthenticator or
    #   RemoteRequestAuthenticator will be used as appropriate.
    def initialize(config = {})
      # stringify symbol keys
      given_config = config.stringify_symbol_keys
      # build a configuration which discards any irrelevant parts of the given config (small memory usage matters here)
      @config = {}
      if given_config['private_key_file'] && !given_config['private_key']
        given_config['private_key'] = File.read(given_config['private_key_file'])
      end
      @config['private_key'] = case given_config['private_key']
       when nil
         nil
       when String
         OpenSSL::PKey::RSA.new(given_config['private_key'])
       when OpenSSL::PKey::RSA
         given_config['private_key']
       else
         raise MAuth::Client::ConfigurationError, "unrecognized value given for 'private_key' - this may be a " \
           "String, a OpenSSL::PKey::RSA, or omitted; instead got: #{given_config['private_key'].inspect}"
      end
      @config['app_uuid'] = given_config['app_uuid']
      @config['mauth_baseurl'] = given_config['mauth_baseurl']
      @config['mauth_api_version'] = given_config['mauth_api_version']
      @config['logger'] = given_config['logger'] || begin
        if Object.const_defined?('Rails') && Rails.logger
          Rails.logger
        else
          require 'logger'
          is_win = RUBY_PLATFORM =~ /mswin|windows|mingw32|cygwin/i
          null_device = is_win ? 'NUL' : '/dev/null'
          ::Logger.new(File.open(null_device, File::WRONLY))
        end
      end

      request_config = { timeout: 10, open_timeout: 10 }
      request_config.merge!(symbolize_keys(given_config['faraday_options'])) if given_config['faraday_options']
      @config['faraday_options'] = { request: request_config } || {}
      @config['ssl_certs_path'] = given_config['ssl_certs_path'] if given_config['ssl_certs_path']
      @config['v2_only_authenticate'] = given_config['v2_only_authenticate'].to_s.downcase == 'true'
      @config['v2_only_sign_requests'] = given_config['v2_only_sign_requests'].to_s.downcase == 'true'

      # if 'authenticator' was given, don't override that - including if it was given as nil / false
      if given_config.key?('authenticator')
        @config['authenticator'] = given_config['authenticator']
      else
        if client_app_uuid && private_key
          # MAuth::Client can authenticate locally if it's provided a client_app_uuid and private_key
          @config['authenticator'] = LocalAuthenticator
        else
          # otherwise, it will authenticate remotely (requests only)
          @config['authenticator'] = RemoteRequestAuthenticator
        end
      end
      extend @config['authenticator'] if @config['authenticator']
    end

    def logger
      @config['logger']
    end

    def client_app_uuid
      @config['app_uuid']
    end

    def mauth_baseurl
      @config['mauth_baseurl'] || raise(MAuth::Client::ConfigurationError, "no configured mauth_baseurl!")
    end

    def mauth_api_version
      @config['mauth_api_version'] || raise(MAuth::Client::ConfigurationError, "no configured mauth_api_version!")
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

    def assert_private_key(err)
      raise err unless private_key
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
