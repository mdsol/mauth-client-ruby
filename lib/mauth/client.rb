require 'uri'
require 'openssl'
require 'base64'
require 'json'
require 'yaml'
require 'mauth/core_ext'
require 'mauth/autoload'
require 'mauth/dice_bag/mauth_templates'
require 'mauth/version'
require 'mauth/v2'

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
  # mAuth client was unable to verify the authenticity of a signed object (this does NOT mean the
  # object is inauthentic). typically due to a failure communicating with the mAuth service, in
  # which case the error may include the attribute mauth_service_response - a response from
  # the mauth service (if it was contactable at all), which may contain more information about
  # the error.
  class UnableToAuthenticateError < StandardError
    # the response from the MAuth service encountered when attempting to retrieve authentication
    attr_accessor :mauth_service_response
  end

  # used to indicate that an object was expected to be validly signed but its signature does not
  # match its contents, and so is inauthentic.
  class InauthenticError < StandardError
  end

  # Used when the incoming request does not contain any mAuth related information
  class MauthNotPresent < StandardError
  end

  # required information for signing was missing
  class UnableToSignError < StandardError
  end

  # used when an object has the V1 headers but not the V2 headers and the
  # V2_ONLY_AUTHENTICATE variable is set to true.
  class MissingV2Error < StandardError
  end

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

    # methods to sign requests and responses. part of MAuth::Client
    module Signer
      # takes an outgoing request or response object, and returns an object of the same class
      # whose headers are updated to include mauth's signature headers
      def signed(object, attributes = {})
        object.merge_headers(signed_headers(object, attributes))
      end

      # signs with v1 only. used when signing responses to v1 requests.
      def signed_v1(object, attributes = {})
        object.merge_headers(signed_headers_v1(object, attributes))
      end

      # takes a signable object (outgoing request or response). returns a hash of headers to be
      # applied to the object which comprises its signature.
      def signed_headers(object, attributes = {})
        if v2_only_sign_requests?
          signed_headers_v2(object, attributes)
        else # by default sign with both the v1 and v2 protocol
          signed_headers_v1(object, attributes).merge(signed_headers_v2(object, attributes))
        end
      end

      def signed_headers_v1(object, attributes = {})
        attributes = { time: Time.now.to_i.to_s, app_uuid: client_app_uuid }.merge(attributes)
        string_to_sign = object.string_to_sign_v1(attributes)
        signature = self.signature(string_to_sign)
        { 'X-MWS-Authentication' => "#{MWS_TOKEN} #{client_app_uuid}:#{signature}", 'X-MWS-Time' => attributes[:time] }
      end

      def signature(string_to_sign)
        assert_private_key(UnableToSignError.new('mAuth client cannot sign without a private key!'))
        Base64.encode64(private_key.private_encrypt(string_to_sign)).delete("\n")
      end
    end
    include Signer

    # methods common to RemoteRequestAuthenticator and LocalAuthenticator
    module Authenticator
      ALLOWED_DRIFT_SECONDS = 300

      # takes an incoming request or response object, and returns whether
      # the object is authentic according to its signature.
      def authentic?(object)
        log_authentication_request(object)
        begin
          authenticate!(object)
          true
        rescue InauthenticError, MauthNotPresent, MAuth::MissingV2Error
          false
        end
      end

      # raises InauthenticError unless the given object is authentic. Will only
      # authenticate with v2 if the environment variable V2_ONLY_AUTHENTICATE
      # is set. Otherwise will authenticate with only the highest protocol version present
      def authenticate!(object)
        if object.protocol_version == 2
          authenticate_v2!(object)
        elsif object.protocol_version == 1
          if v2_only_authenticate?
            # If v2 is required but not present and v1 is present we raise MissingV2Error
            msg = 'This service requires mAuth v2 mcc-authentication header but only v1 x-mws-authentication is present'
            logger.error(msg)
            raise MAuth::MissingV2Error, msg
          end

          authenticate_v1!(object)
        else
          sub_str = v2_only_authenticate? ? '' : 'X-MWS-Authentication header is blank, '
          msg = "Authentication Failed. No mAuth signature present; #{sub_str}MCC-Authentication header is blank."
          logger.warn("mAuth signature not present on #{object.class}. Exception: #{msg}")
          raise MauthNotPresent, msg
        end
      end

      private

      # Note: This log is likely consumed downstream and the contents SHOULD NOT
      # be changed without a thorough review of downstream consumers.
      def log_authentication_request(object)
        object_app_uuid = object.signature_app_uuid || '[none provided]'
        object_token = object.signature_token || '[none provided]'
        logger.info(
          "Mauth-client attempting to authenticate request from app with mauth" \
          " app uuid #{object_app_uuid} to app with mauth app uuid #{client_app_uuid}" \
          " using version #{object_token}."
        )
      end

      def log_inauthentic(object, message)
        logger.error("mAuth signature authentication failed for #{object.class}. Exception: #{message}")
      end

      def time_within_valid_range!(object, time_signed, now = Time.now)
        return if  (-ALLOWED_DRIFT_SECONDS..ALLOWED_DRIFT_SECONDS).cover?(now.to_i - time_signed)

        msg = "Time verification failed. #{time_signed} not within #{ALLOWED_DRIFT_SECONDS} of #{now}"
        log_inauthentic(object, msg)
        raise InauthenticError, msg
      end

      # V1 helpers
      def authenticate_v1!(object)
        time_valid_v1!(object)
        token_valid_v1!(object)
        signature_valid_v1!(object)
      end

      def authentication_present_v1?(object)
        !object.x_mws_authentication.to_s.strip.empty?
      end

      def time_valid_v1!(object)
        if object.x_mws_time.nil?
          msg = 'Time verification failed. No x-mws-time present.'
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
        time_within_valid_range!(object, object.x_mws_time.to_i)
      end

      def token_valid_v1!(object)
        return if object.signature_token == MWS_TOKEN

        msg = "Token verification failed. Expected #{MWS_TOKEN}; token was #{object.signature_token}"
        log_inauthentic(object, msg)
        raise InauthenticError, msg
      end

    end
    include Authenticator

    # methods to verify the authenticity of signed requests and responses locally, retrieving
    # public keys from the mAuth service as needed
    module LocalAuthenticator
      private

      def signature_valid_v1!(object)
        # We are in an unfortunate situation in which Euresource is percent-encoding parts of paths, but not
        # all of them.  In particular, Euresource is percent-encoding all special characters save for '/'.
        # Also, unfortunately, Nginx unencodes URIs before sending them off to served applications, though
        # other web servers (particularly those we typically use for local testing) do not.  The various forms
        # of the expected string to sign are meant to cover the main cases.
        # TODO:  Revisit and simplify this unfortunate situation.

        original_request_uri = object.attributes_for_signing[:request_url]

        # craft an expected string-to-sign without doing any percent-encoding
        expected_no_reencoding = object.string_to_sign_v1(time: object.x_mws_time, app_uuid: object.signature_app_uuid)

        # do a simple percent reencoding variant of the path
        object.attributes_for_signing[:request_url] = CGI.escape(original_request_uri.to_s)
        expected_for_percent_reencoding = object.string_to_sign_v1(time: object.x_mws_time, app_uuid: object.signature_app_uuid)

        # do a moderately complex Euresource-style reencoding of the path
        object.attributes_for_signing[:request_url] = euresource_escape(original_request_uri.to_s)
        expected_euresource_style_reencoding = object.string_to_sign_v1(time: object.x_mws_time, app_uuid: object.signature_app_uuid)

        # reset the object original request_uri, just in case we need it again
        object.attributes_for_signing[:request_url] = original_request_uri

        pubkey = OpenSSL::PKey::RSA.new(retrieve_public_key(object.signature_app_uuid))
        begin
          actual = pubkey.public_decrypt(Base64.decode64(object.signature))
        rescue OpenSSL::PKey::PKeyError => e
          msg = "Public key decryption of signature failed! #{e.class}: #{e.message}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end

        unless expected_no_reencoding == actual || expected_euresource_style_reencoding == actual || expected_for_percent_reencoding == actual
          msg = "Signature verification failed for #{object.class}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
      end

      # Note: RFC 3986 (https://www.ietf.org/rfc/rfc3986.txt) reserves the forward slash "/"
      #   and number sign "#" as component delimiters. Since these are valid URI components,
      #   they are decoded back into characters here to avoid signature invalidation
      def euresource_escape(str)
        CGI.escape(str).gsub(/%2F|%23/, '%2F' => '/', '%23' => '#')
      end

      def retrieve_public_key(app_uuid)
        retrieve_security_token(app_uuid)['security_token']['public_key_str']
      end

      def retrieve_security_token(app_uuid)
        security_token_cacher.get(app_uuid)
      end

      def security_token_cacher
        @security_token_cacher ||= SecurityTokenCacher.new(self)
      end
      class SecurityTokenCacher
        class ExpirableSecurityToken < Struct.new(:security_token, :create_time)
          CACHE_LIFE = 60
          def expired?
            create_time + CACHE_LIFE < Time.now
          end
        end
        def initialize(mauth_client)
          @mauth_client = mauth_client
          # TODO: should this be UnableToSignError?
          @mauth_client.assert_private_key(UnableToAuthenticateError.new("Cannot fetch public keys from mAuth service without a private key!"))
          @cache = {}
          require 'thread'
          @cache_write_lock = Mutex.new
        end

        def get(app_uuid)
          if !@cache[app_uuid] || @cache[app_uuid].expired?
            # url-encode the app_uuid to prevent trickery like escaping upward with ../../ in a malicious
            # app_uuid - probably not exploitable, but this is the right way to do it anyway.
            # use UNRESERVED instead of UNSAFE (the default) as UNSAFE doesn't include /
            url_encoded_app_uuid = URI.escape(app_uuid, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
            begin
              response = signed_mauth_connection.get("/mauth/#{@mauth_client.mauth_api_version}/security_tokens/#{url_encoded_app_uuid}.json")
            rescue ::Faraday::Error::ConnectionFailed, ::Faraday::Error::TimeoutError => e
              msg = "mAuth service did not respond; received #{e.class}: #{e.message}"
              @mauth_client.logger.error("Unable to authenticate with MAuth. Exception #{msg}")
              raise UnableToAuthenticateError, msg
            end
            if response.status == 200
              begin
                security_token = JSON.parse(response.body)
              rescue JSON::ParserError => e
                msg =  "mAuth service responded with unparseable json: #{response.body}\n#{e.class}: #{e.message}"
                @mauth_client.logger.error("Unable to authenticate with MAuth. Exception #{msg}")
                raise UnableToAuthenticateError, msg
              end
              @cache_write_lock.synchronize do
                @cache[app_uuid] = ExpirableSecurityToken.new(security_token, Time.now)
              end
            elsif response.status == 404
              # signing with a key mAuth doesn't know about is considered inauthentic
              raise InauthenticError, "mAuth service responded with 404 looking up public key for #{app_uuid}"
            else
              @mauth_client.send(:mauth_service_response_error, response)
            end
          end
          @cache[app_uuid].security_token
        end

        private

        def signed_mauth_connection
          require 'faraday'
          require 'mauth/faraday'
          @mauth_client.faraday_options[:ssl] = { ca_path: @mauth_client.ssl_certs_path } if @mauth_client.ssl_certs_path
          @signed_mauth_connection ||= ::Faraday.new(@mauth_client.mauth_baseurl, @mauth_client.faraday_options) do |builder|
            builder.use MAuth::Faraday::MAuthClientUserAgent
            builder.use MAuth::Faraday::RequestSigner, 'mauth_client' => @mauth_client
            builder.adapter ::Faraday.default_adapter
          end
        end
      end
    end

    # methods for remotely authenticating a request by sending it to the mauth service
    module RemoteRequestAuthenticator
      private

      # takes an incoming request object (no support for responses currently), and errors if the
      # object is not authentic according to its signature
      def signature_valid_v1!(object)
        raise ArgumentError, "Remote Authenticator can only authenticate requests; received #{object.inspect}" unless object.is_a?(MAuth::Request)
        authentication_ticket = {
          'verb' => object.attributes_for_signing[:verb],
          'app_uuid' => object.signature_app_uuid,
          'client_signature' => object.signature,
          'request_url' => object.attributes_for_signing[:request_url],
          'request_time' => object.x_mws_time,
          'b64encoded_body' => Base64.encode64(object.attributes_for_signing[:body] || '')
        }
        make_mauth_request(authentication_ticket)
      end

      def make_mauth_request(authentication_ticket)
        begin
          response = mauth_connection.post("/mauth/#{mauth_api_version}/authentication_tickets.json", 'authentication_ticket' => authentication_ticket)
        rescue ::Faraday::Error::ConnectionFailed, ::Faraday::Error::TimeoutError => e
          msg = "mAuth service did not respond; received #{e.class}: #{e.message}"
          logger.error("Unable to authenticate with MAuth. Exception #{msg}")
          raise UnableToAuthenticateError, msg
        end
        if (200..299).cover?(response.status)
          nil
        elsif response.status == 412 || response.status == 404
          # the mAuth service responds with 412 when the given request is not authentically signed.
          # older versions of the mAuth service respond with 404 when the given app_uuid
          # does not exist, which is also considered to not be authentically signed. newer
          # versions of the service respond 412 in all cases, so the 404 check may be removed
          # when the old version of the mAuth service is out of service.
          raise InauthenticError, "The mAuth service responded with #{response.status}: #{response.body}"
        else
          mauth_service_response_error(response)
        end
      end

      def mauth_connection
        require 'faraday'
        require 'faraday_middleware'
        @mauth_connection ||= ::Faraday.new(mauth_baseurl, faraday_options) do |builder|
          builder.use MAuth::Faraday::MAuthClientUserAgent
          builder.use FaradayMiddleware::EncodeJson
          builder.adapter ::Faraday.default_adapter
        end
      end
    end
  end
end
