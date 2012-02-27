require 'uri'
require 'openssl'
require 'base64'
require 'json'

module MAuth
  # mAuth client was unable to verify the authenticity of a signed object (this does NOT mean the 
  # object is inauthentic). typically due to a failure communicating with the mAuth service, in 
  # which case the error may include the attribute mauth_service_response - a response from 
  # the mauth service (if it was contactable at all), which may contain more information about 
  # the error. 
  class UnableToAuthenticateError < StandardError
    attr_accessor :mauth_service_response
  end

  # used to indicate that an object was expected to be validly signed but its signature does not 
  # match its contents, and so is inauthentic. 
  class InauthenticError < StandardError
  end

  # required information for signing was missing 
  class UnableToSignError < StandardError
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
    MWS_TOKEN = 'MWS'

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
    def initialize(config={})
      require 'backports/rails/hash'
      given_config = config.stringify_keys
      # build a configuration which discards any irrelevant parts of the given config (small memory usage matters here) 
      @config = {}
      @config['private_key'] = case given_config['private_key']
      when nil
        nil
      when String
        OpenSSL::PKey::RSA.new(given_config['private_key'])
      when OpenSSL::PKey::RSA
        given_config['private_key']
      else
        raise ArgumentError, "unrecognized value given for 'private_key' - this may be a String, a OpenSSL::PKey::RSA, or omitted; instead got: #{given_config['private_key'].inspect}"
      end
      @config['app_uuid'] = given_config['app_uuid']
      @config['mauth_baseurl'] = given_config['mauth_baseurl']
      @config['mauth_api_version'] = given_config['mauth_api_version']
      @config['logger'] = given_config['logger'] || begin
        if Object.const_defined?('Rails')
          Rails.logger
        else
          require 'logger'
          #::Logger.new(STDERR)
          ::Logger.new(File.open('/dev/null', File::WRONLY))
        end
      end
      @config['faraday_options'] = {:timeout => 1, :open_timeout => 1}.merge(given_config['faraday_options'] || {})

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
      @config['mauth_baseurl'] || raise("no configured mauth_baseurl!")
    end
    def mauth_api_version
      @config['mauth_api_version'] || raise("no configured mauth_api_version!")
    end
    def private_key
      @config['private_key']
    end
    def faraday_options
      @config['faraday_options']
    end
    def assert_private_key(err)
      unless private_key
        raise err
      end
    end

    private
    def mauth_service_response_error(response)
      message = "mAuth service responded with #{response.status}: #{response.body}"
      logger.error(message)
      error = UnableToAuthenticateError.new(message)
      error.mauth_service_response = response || response_error
      raise error
    end

    # methods to sign requests and responses. part of MAuth::Client 
    module Signer
      # takes an outgoing request or response object, and returns an object of the same class 
      # whose headers are updated to include mauth's signature headers 
      def signed(object, attributes={})
        object.merge_headers(signed_headers(object, attributes))
      end

      # takes a signable object (outgoing request or response). returns a hash of headers to be 
      # applied tothe object which comprise its signature. 
      def signed_headers(object, attributes={})
        assert_private_key(UnableToSignError.new("mAuth client cannot sign without a private key!"))
        attributes = {:time => Time.now.to_i.to_s, :app_uuid => client_app_uuid}.merge(attributes)
        signature = self.signature(object, attributes)
        {'X-MWS-Authentication' => "#{MWS_TOKEN} #{client_app_uuid}:#{signature}", 'X-MWS-Time' => attributes[:time]}
      end

      # takes a signable object (outgoing request or response). returns a mauth signature string 
      # for that object. 
      def signature(object, attributes={})
        attributes = {:time => Time.now.to_i.to_s, :app_uuid => client_app_uuid}.merge(attributes)
        signature = Base64.encode64(private_key.private_encrypt(object.string_to_sign(attributes))).gsub("\n","")
      end
    end
    include Signer

    # methods common to RemoteRequestAuthenticator and LocalAuthenticator 
    module Authenticator
      ALLOWED_DRIFT_SECONDS = 300

      # takes an incoming request or response object, and returns whether 
      # the object is authentic according to its signature. 
      def authentic?(object)
        begin
          authenticate!(object)
          true
        rescue InauthenticError
          logger.error "mAuth signature authentication failed for #{object.class}. encountered error:"
          $!.message.split("\n").each{|l| logger.error "\t#{l}" }
          false
        end
      end

      # raises InauthenticError unless the given object is authentic 
      def authenticate!(object)
        time_valid!(object)
        token_valid!(object)
        signature_valid!(object)
      end

      private
      def time_valid!(object, now=Time.now)
        if object.x_mws_time.nil?
          raise InauthenticError, "Time verification failed for #{object.class}. No x-mws-time present."
        elsif !(-ALLOWED_DRIFT_SECONDS..ALLOWED_DRIFT_SECONDS).include?(now.to_i - object.x_mws_time.to_i)
          raise InauthenticError, "Time verification failed for #{object.class}. #{object.x_mws_time} not within #{ALLOWED_DRIFT_SECONDS} of #{now}"
        end
      end
      def token_valid!(object)
        unless object.signature_token==MWS_TOKEN
          raise InauthenticError, "Token verification failed for #{object.class}. Expected #{MWS_TOKEN.inspect}; token was #{object.signature_token}"
        end
      end
    end
    include Authenticator

    # methods to verify the authenticity of signed requests and responses locally, retrieving 
    # public keys from the mAuth service as needed 
    module LocalAuthenticator
      private
      def signature_valid!(object)
        expected = object.string_to_sign(:time => object.x_mws_time, :app_uuid => object.signature_app_uuid)
        pubkey = OpenSSL::PKey::RSA.new(retrieve_public_key(object.signature_app_uuid))
        begin
          actual = pubkey.public_decrypt(Base64.decode64(object.signature))
        rescue OpenSSL::PKey::PKeyError
          raise InauthenticError, "Public key decryption of signature failed!\n#{$!.class}: #{$!.message}"
        end
        # TODO: time-invariant comparison instead of #== ? 
        unless expected == actual
          raise InauthenticError, "Signature verification failed for #{object.class}"
        end
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
          CACHE_LIFE=60
          def expired?
            create_time + CACHE_LIFE < Time.now
          end
        end
        def initialize(mauth_client)
          @mauth_client = mauth_client
          @mauth_client.assert_private_key(UnableToAuthenticateError.new("Cannot fetch public keys from mAuth service without a private key!")) # TODO should this be UnableToSignError? 
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
            rescue ::Faraday::Error::ConnectionFailed
              raise UnableToAuthenticateError, "mAuth service did not respond; received #{$!.class}: #{$!.message}"
            end
            if response.status==200
              begin
                security_token = JSON.parse(response.body)
              rescue JSON::ParserError
                raise UnableToAuthenticateError, "mAuth service responded with unparseable json: #{response.body}\n#{$!.class}: #{$!.message}"
              end
              @cache_write_lock.synchronize do
                @cache[app_uuid] = ExpirableSecurityToken.new(security_token, Time.now)
              end
            elsif response.status==404
              @mauth_client.logger.error("mAuth service responded with 404 looking up public key for #{app_uuid}")
              # signing with a key mAuth doesn't know about is considered inauthentic 
              raise InauthenticError
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
          @signed_mauth_connection ||= ::Faraday.new(@mauth_client.mauth_baseurl, @mauth_client.faraday_options) do |builder|
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
      def signature_valid!(object)
        raise ArgumentError, "Remote Authenticator can only authenticate requests; received #{object.inspect}" unless object.is_a?(MAuth::Request)
        authentication_ticket = {
          'verb' => object.attributes_for_signing[:verb],
          'app_uuid' => object.signature_app_uuid,
          'client_signature' => object.signature,
          'request_url' => object.attributes_for_signing[:request_url],
          'request_time' => object.x_mws_time,
          'b64encoded_body' => Base64.encode64(object.attributes_for_signing[:body] || '')
        }
        begin
          response = mauth_connection.post("/mauth/#{mauth_api_version}/authentication_tickets.json", {"authentication_ticket" => authentication_ticket})
        rescue ::Faraday::Error::ConnectionFailed
          raise UnableToAuthenticateError, "mAuth service did not respond; received #{$!.class}: #{$!.message}"
        end
        if (200..299).include?(response.status)
          nil
        elsif response.status==412
          raise InauthenticError, "The mAuth service responded with #{response.status}: #{response.body}"
        else
          mauth_service_response_error(response)
        end
      end

      def mauth_connection
        require 'faraday'
        require 'faraday_middleware'
        @mauth_connection ||= ::Faraday.new(mauth_baseurl, faraday_options) do |builder|
          builder.use FaradayMiddleware::EncodeJson
          builder.adapter ::Faraday.default_adapter
        end
      end
    end
  end
end