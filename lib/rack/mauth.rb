require 'json'
require 'base64'
require 'uri'
require 'net/https'
require 'thread'
require 'bundler/setup'
require 'mauth_signer'
require 'rest_client'

module Medidata
  class MAuthMiddleware

    # Middleware initializer
    def initialize(app, config = {})
      @app = app
      @config = MAuthMiddlewareConfig.new(config)
      @mauth_verifiers_manager = MAuthVerifiersManager.new(@config) if can_authenticate_locally?
      @mauth_remote_verifier = MAuthRemoteVerifier.new(@config)
    end

    # Method called by app using middleware
    def call(env)
      if should_authenticate?(env)
        authenticated?(env) ? @app.call(env) : unauthenticated_response
      else
        @app.call(env)
      end
    end

    protected
      # Determine if the given endpoint should be authenticated.
      def should_authenticate?(env)        
        if @config.should_authentication_check.nil?
          return true
        else
          return @config.should_authentication_check.call(env)
        end
      end
      
      # Rack-mauth can authenticate locally if the middleware user provided an self_app_uuid and self_private_key
      # self_app_uuid is the app_uuid (in MAuth db) of app using this middleware
      # self_private_key is the private of app using this middleware which corresponds to public key of app_uuid in MAuth db
      def can_authenticate_locally?
        !@config.self_app_uuid.nil? && !@config.self_private_key.nil?
      end

      # Parse HTTP_X_MWS_AUTHENTICATION header for authentication data
      def env_authentication_data(env)
        mws_token, auth_info =  env['HTTP_X_MWS_AUTHENTICATION'].to_s.split(' ')
        app_uuid, digest = auth_info.split(':') if auth_info
        [mws_token, app_uuid, digest]
      end
      
      # Is the request authentic?
      def authenticated?(env)
        mws_token,app_uuid,digest = env_authentication_data(env)

        return false unless app_uuid && digest && mws_token == 'MWS'

        #TODO Find a rack env like 'PATH_INFO' that all servers will accept as the relative URI
        # ie rack and rails have different REQUEST_URI
        params = {
          :app_uuid    => app_uuid,
          :digest      => digest,
          :verb        => env['REQUEST_METHOD'],
          :request_url => env['PATH_INFO'],
          :time        => env['HTTP_X_MWS_TIME'],
          :body        => ''
        }
        if %w(POST PUT).include? env['REQUEST_METHOD']
          params[:body] = env['rack.input'].read
          env['rack.input'].rewind
        end

        if can_authenticate_locally?
          @mauth_verifiers_manager.authenticate_request(digest, params)
        else
          @mauth_remote_verifier.authenticate_request(digest, params)
        end
      end

      # Response returned to requesting app when request is inauthentic
      def unauthenticated_response
        [401, {'Content-Type' => 'text/plain'}, ['Unauthorized']]
      end
    end # of MAuthMiddleware
    
    # Manages configuration for middleware
    class MAuthMiddlewareConfig
      attr_reader :mauth_baseurl, :mauth_api_version, :self_app_uuid, :self_private_key, :should_authentication_check
      
      def initialize(config = {})
        @mauth_baseurl = config[:mauth_baseurl] || raise(ArgumentError, 'mauth_baseurl: missing base url')
        @mauth_api_version = config[:mauth_api_version] || raise(ArgumentError, 'mauth_api_version: missing api mauth_api_version')
        verify_mauth_baseurl

        @self_app_uuid, @self_private_key = config[:app_uuid], config[:private_key]
        @should_authentication_check = config[:should_authentication_check]
      end
      
      # Write to log
      def log(str_to_log)
        Rails.logger.info("rack-mauth: " + str_to_log) if can_log?
      end
       
      protected
        # Need to ensure the complete base url is valid
        def verify_mauth_baseurl
          begin
            parsed = URI.parse(@mauth_baseurl)
            raise ArgumentError, "mauth_baseurl: #{@mauth_baseurl} must contain a scheme and host" unless parsed.host && parsed.scheme
          rescue URI::InvalidURIError
            raise ArgumentError, "mauth_baseurl: #{@mauth_baseurl} in not a valid uri"
          end
        end
        
        # Can we write to the Rails log
        def can_log?
          @can_log ||= (defined?(Rails) && Rails.respond_to?(:logger))
        end
    end # of MAuthMiddleware
    
    # Manages cached MAuth verifiers for use in local authentication
    class MAuthVerifiersManager
      def initialize(config = nil)
        raise ArgumentError, 'must provide an MAuthMiddlewareConfig' if config.nil?
        
        @config = config
        @cached_verifiers_mutex = Mutex.new
        @cached_verifiers = {}
        @mauth_signer_for_self = MAuth::Signer.new(:private_key => @config.self_private_key)
      end
      
      # Rack-mauth does its own authentication
      def authenticate_request(digest, params)
        verifier = verifier_for_app(params[:app_uuid])
        !verifier.nil? && verifier.verify_request(digest, params)
      end
      
      protected
        # URL for security tokens
        def security_token_url(app_uuid)
          URI.parse(@config.mauth_baseurl + security_token_path(app_uuid))
        end
        
        # Path to security tokens in mAuth
        def security_token_path(app_uuid)
          "/mauth/#{@config.mauth_api_version}/security_tokens/#{app_uuid}.json"
        end
        
        # Synchronize ivars
        def synchronize
          @cached_verifiers_mutex.synchronize { yield }
        end
        
        # Add, replace or delete signer from cache
        # If add/replace, then update refreshness time
        def update_cache(app_uuid, new_verifier, action)
          synchronize do
            if action == :delete
              @cached_verifiers.delete(app_uuid)
            elsif action == :add
              @cached_verifiers[app_uuid] = {:verifier => new_verifier, :last_refresh => Time.now} # cached signers are actually hashes of the form {:signer => the_signer, :last_refresh => the time of last refresh}
            end
          end
        end

        # Make a new signer with info. (i.e. public key) from MAuth
        # if MAuth can find, then add to/replace in cache
        # if MAuth cannot find public key, then remove from cache
        # if an error occurs (e.g. MAuth 500 or JSON parse error), do nothing
        def refresh_verifier(app_uuid)
          ret = get_remote_public_key(app_uuid)

          if ret[:response_code] == :found
            update_cache(app_uuid, new_signer = MAuth::Signer.new(:public_key => ret[:public_key]), :add)
          elsif ret[:status_code] == :not_found
            update_cache(app_uuid, nil, :delete)
          end
        end

        # Cache for a signer with a given app_uuid expires every minute
        def verifier_expired?(app_uuid)
          verifier = cached_verifier(app_uuid)
          verifier.nil? || verifier[:last_refresh] < (Time.now - 60)
        end

        # Fetch signer from cache
        def cached_verifier(app_uuid)
          synchronize { @cached_verifiers[app_uuid] }
        end

        # Find the MAuth::Signer for app with given app_uuid
        # Find either in cache or generate with remote data
        def verifier_for_app(app_uuid)
          refresh_verifier(app_uuid) if verifier_expired?(app_uuid)
          verifier = cached_verifier(app_uuid)

          if verifier
            return verifier[:verifier] # cached verifier are actually hashes of the form {:verifier => the_verifier, :last_refresh => the time of last refresh}
          else
            @config.log("Cannot find public key for app with uuid #{app_uuid} locally or in MAuth")
            return nil
          end
        end
            
        # Formulate return values given response
        def formulate_return_values_from_mauth(response)
          return {:response_code => :error, :body => nil} if response.nil?
          
          code = response.code.to_i
          return {:response_code => :found, :body => response.body} if code == 200
          return {:response_code => :not_found, :body => nil} if code == 404
          return {:response_code => :error, :body => nil} if code >= 500
          
          return {:response_code => :error, :body => nil} #fallback return code
        end
        
        # Get remote security token from MAuth (for the purposes of local authentication)
        def get_remote_security_token(app_uuid)
          headers = @mauth_signer_for_self.signed_request_headers(:app_uuid => @config.self_app_uuid, :verb => 'GET', :request_url => security_token_path(app_uuid))
          response = get(security_token_url(app_uuid), {:headers => headers})
          formulate_return_values_from_mauth(response)
        end 
      
        # Get remote public key for given app_uuid from MAuth (for the purposes of local authentication)
        # Fetches a security token and simply extracts the public key from it
        def get_remote_public_key(app_uuid)
          ret = get_remote_security_token(app_uuid)
          
          ret[:public_key] = nil
          unless ret[:body].nil?
            begin
              ret[:public_key] = JSON.parse(ret[:body])['security_token']['public_key_str']
            rescue JSON::ParserError, TypeError
              ret = {:response_code => :error, :public_key => nil}
              @config.log "Cannot parse JSON response from MAuth for security token for app_uuid #{app_uuid} request "
            end
          end
          
          ret          
        end
      
        # Generic get
        def get(from_url, options = {})
          begin
            opts = {:timeout => 2, :verify_ssl => (OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT)}
            opts.merge!({:headers => options[:headers]}) if options[:headers]
            response = RestClient::Resource.new(from_url.to_s, opts).get
            return response.net_http_res
          rescue RestClient::Exception, Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError,
                 Errno::ECONNREFUSED, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError,
                 OpenSSL::SSL::SSLError => e
            @config.log "Attempt to GET from #{from_url.path} threw exception:  #{e.message}"
            return nil
          end
        end
    end # of MAuthVerifiersManager
        
    # Ask MAuth for authenticate remotely; probably won't be used much as MAuth serves public keys
    class MAuthRemoteVerifier
      def initialize(config = nil)
        raise ArgumentError, 'must provide an MAuthMiddlewareConfig' if config.nil?
        @config = config
      end
      
      # Ask mAuth to authenticate
      def authenticate_request(digest, params)

        # TODO: refactor data keys to more closely match params
        data = {
          'verb' => params[:verb],
          'app_uuid' => params[:app_uuid],
          'client_signature' => digest,
          'request_url' => params[:request_url],
          'request_time' => params[:time],
          'b64encoded_body' => Base64.encode64(params[:body])
        }

        # Post to endpoint
        response = post(authentication_url, {"authentication_ticket" => data})

        if response.nil?
          @config.log "Remote authen. returned nil response"
          return false
        elsif response.code.to_i != 204
          @config.log "Attempt to authenticate remotely failed with status code #{response.code}"
          return false
        else
          return true
        end
      end
      
      protected
        # URL to which authenication tickets are posted for the purpose of remote authentication with mAuth
        def authentication_url
          URI.parse(@config.mauth_baseurl + "/mauth/#{@config.mauth_api_version}/authentication_tickets.json")
        end
      
        # Generic post
        def post(to_url, post_data, options = {})
          begin
            opts = {:timeout => 2, :verify_ssl => (OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT)}
            opts.merge!({:headers => options[:headers]}) if options[:headers]
            response = RestClient::Resource.new(to_url.to_s, opts).post(post_data.to_json, :content_type => 'application/json')
            return response.net_http_res            
          rescue RestClient::Exception, Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError,
                 Errno::ECONNREFUSED, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError,
                 OpenSSL::SSL::SSLError => e
            @config.log "Attempt to POST to #{to_url.path} threw exception:  #{e.message}"
            return nil
          end
        end
    end # of MAuthRemoteVerifier
    
end
