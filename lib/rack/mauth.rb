require 'json'
require 'base64'
require 'uri'
require 'net/https'
require 'thread'
require 'bundler/setup'
require 'mauth_signer'

module Medidata
  class MAuthMiddleware

    # Middleware initializer
    def initialize(app, config = {})
      @mauth_baseurl = config[:mauth_baseurl] || (raise ArgumentError, 'missing base url')
      @version = config[:version] || (raise ArgumentError, 'missing api version')
      verify_mauth_baseurl
      
      @app, @self_app_uuid, @private_key = app, config[:app_uuid], config[:private_key]
      @path_whitelist, @whitelist_exceptions = config[:path_whitelist], config[:whitelist_exceptions]
      @cached_signers_mutex = Mutex.new
      @cached_signers = {}
      @mauth_signer_for_self = MAuth::Signer.new(:private_key => @private_key) if can_authenticate_locally?      
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
      # Need to ensure the complete base url is valid
      def verify_mauth_baseurl
        parsed = URI.parse(@mauth_baseurl)
        raise ArgumentError, 'invalid base url' unless parsed.host && parsed.scheme
      end

      # URL to which authenication tickets are posted for the purpose of remote authentication with mAuth
      def authentication_url
        URI.parse(@mauth_baseurl + "/mauth/#{@version}/authentication_tickets.json")
      end

      # Path to security tokens in mAuth
      def security_token_path(app_uuid)
        "/mauth/#{@version}/security_tokens/#{app_uuid}.json"
      end

      # URL for security tokens
      def security_token_url(app_uuid)
        URI.parse(@mauth_baseurl + security_token_path(app_uuid))
      end

      # Synchronize ivars
      def synchronize
        @cached_signers_mutex.synchronize { yield }
      end

      # Parse secret from mAuth
      def parse_secret(secret_from_mauth)
        begin
          remote_token = JSON.parse(secret_from_mauth)
          key = remote_token['security_token']['app_uuid']
          val = remote_token['security_token']['private_key']
          return {key => {:private_key => val}}
        rescue JSON::ParserError, TypeError
          log "Cannot parse JSON response for shared secret request from mAuth:  #{secret_from_mauth}"
        end
      end

      #return the value inside the cache if remote mAuth responds 500
      def mauth_server_error(app_uuid)
        app_token = fetch_cached_token(app_uuid)
        if app_token.nil?
          log "Couldn't find app_uuid #{app_uuid} in local cache and mAuth experienced an error"
          return nil
        end
        return {'security_token' => {app_uuid => {'private_key' => fetch_private_key(app_uuid)}}}
      end

      # Determine if the given endpoint should be authenticated. Perhaps use env['PATH_INFO']
      def should_authenticate?(env)
        return true unless @path_whitelist

        path_info = env['PATH_INFO']
        any_matches = @path_whitelist.any?{|re| path_info =~ re}
        any_exceptions = @whitelist_exceptions ? @whitelist_exceptions.any?{|re| path_info =~ re} : false

        any_matches && !any_exceptions
      end

      # Rack-mauth can authenticate locally if the middleware user provided an app_uuid and private_key
      def can_authenticate_locally?
        @self_app_uuid && @private_key
      end

      # Is the request authentic?
      def authenticated?(env)
        mws_token, auth_info =  env['HTTP_AUTHORIZATION'].to_s.split(' ')
        app_uuid, digest = auth_info.split(':') if auth_info

        return false unless app_uuid && digest && mws_token == 'MWS'

        #TODO Find a rack env like 'PATH_INFO' that all servers will accept as the relative URI
        # ie rack and rails have different REQUEST_URI
        params = {
          :app_uuid    => app_uuid,
          :digest      => digest,
          :verb        => env['REQUEST_METHOD'],
          :request_url => env['PATH_INFO'],
          :time        => env['HTTP_X_MWS_TIME'],
          :post_data   => ''
        }
        if %w(POST PUT).include? env['REQUEST_METHOD']
          params[:post_data] = env['rack.input'].read
          env['rack.input'].rewind
        end

        if can_authenticate_locally?
          authenticate_locally(digest, params)
        else
          authenticate_remotely(digest, params)
        end
      end

      # Add, replace or delete signer from cache
      # If add/replace, then update refreshness time
      def update_cache(app_uuid, new_signer, action)
        synchronize do
          if action == :delete
            @cached_signers.delete(app_uuid)
          elsif action == :add
            @cached_signers[app_uuid] = {:signer => new_signer, :last_refresh => Time.now} # cached signers are actually hashes of the form {:signer => the_signer, :last_refresh => the time of last refresh}
          end
        end
      end
      
      # Make a new signer with info. (i.e. public key) from MAuth
      # if MAuth returns 200, then add to/replace in cache
      # if MAuth returns 404, then remove from cache
      # if MAuth return 500, do nothing
      def refresh_signer(app_uuid)
        ret = get_remote_public_key(app_uuid)
        
        if ret[:status_code] == 200
          update_cache(app_uuid, new_signer = MAuth::Signer.new(:public_key => ret[:public_key]), :add)
        elsif ret[:status_code] == 404
          update_cache(app_uuid, nil, :delete)
        end
      end
      
      # Cache for a signer with a given app_uuid expires every minute
      def signer_expired?(app_uuid)
        signer = cached_signer(app_uuid)
        signer.nil? || signer[:last_refresh] < (Time.now - 60)
      end
      
      # Fetch signer from cache
      def cached_signer(app_uuid)
        synchronize { @cached_signers[app_uuid] }
      end
      
      # Find the MAuth::Signer for app with given app_uuid
      # Find either in cache or generate with remote data
      def signer_for_app(app_uuid)
        refresh_signer(app_uuid) if signer_expired?(app_uuid)
        signer = cached_signer(app_uuid)
        
        if signer
          return signer[:signer] # cached signers are actually hashes of the form {:signer => the_signer, :last_refresh => the time of last refresh}
        else
          log("Cannot find public key for app with uuid #{app_uuid} locally or in MAuth")
          return nil
        end
      end
      
      # Rack-mauth does its own authentication
      def authenticate_locally(digest, params)
        signer = signer_for_app(params[:app_uuid])
        signer && signer.verify_request(digest, params)
      end

      # Ask mAuth to authenticate
      def authenticate_remotely(digest, params)

        # TODO: refactor data keys to more closely match params
        data = {
          'verb' => params[:verb],
          'app_uuid' => params[:app_uuid],
          'client_signature' => params[:digest],
          'request_url' => params[:request_url],
          'request_time' => params[:time],
          'b64encoded_post_data' => Base64.encode64(params[:post_data])
        }

        # Post to endpoint
        response = post(authentication_url, {"authentication_ticket" => data})

        return false unless response
        if response.code.to_i == 204
          return true
        else
          log "Attempt to authenticate remotely failed with status code #{response.code}"
          return false
        end
      end

      # Response returned to requesting app when request is inauthentic
      def unauthenticated_response
        [401, {'Content-Type' => 'text/plain'}, ['Unauthorized']]
      end
      
      # Returns status code and relevant response.body info given respose
      def according_to(response)
        return {:status_code => 500, :body => nil}  if response.nil?
        
        code = response.code.to_i
        if code == 200
          return {:status_code => 200, :body => response.body}
        elsif code == 404
          return {:status_code => 404, :body => nil}
        elsif code >= 500
          return {:status_code => 500, :body => nil}
        else
          log "Attempt to refresh cache with secret from mAuth responded with #{response.code.to_i} #{response.body}"
          return {:status_code => 500, :body => nil}
        end
      end
      
      # Get remote security token from MAuth (for the purposes of local authentication)
      def get_remote_security_token(app_uuid)
        headers = @mauth_signer_for_self.signed_request_headers(:app_uuid => @self_app_uuid, :verb => 'GET', :request_url => security_token_path(app_uuid))
        response = get(security_token_url(app_uuid), {:headers => headers})
        ret = according_to(response)
        begin
          ret[:body] = JSON.parse(ret[:body]) unless ret[:body].nil?
        rescue JSON::ParserError, TypeError
          ret = {:status_code => 500, :body => nil}
          log "Cannot parse JSON response from MAuth for security token for app_uuid #{app_uuid} request "
        end
        
        return ret
      end
      
      # Get remote public key from MAuth (for the purposes of local authentication)
      def get_remote_public_key(app_uuid)
        ret = get_remote_security_token(app_uuid)
        pub_key = ret[:body].nil? ? nil : ret[:body]['security_token']['public_key_str']
        {:status_code => ret[:status_code], :public_key => pub_key}
      end
      
      # Generic get
      def get(from_url, options = {})
        begin
          http = Net::HTTP.new(from_url.host, from_url.port)
          http.use_ssl = (from_url.scheme == 'https')
          http.read_timeout = 20 #seconds
          headers = options[:headers].nil? ? {} : options[:headers]
          request = Net::HTTP::Get.new(from_url.path, headers)
          response = http.start {|h| h.request(request) }
          return response
        rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, OpenSSL::SSL::SSLError,
               Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError => e
          log "Attempt to GET from #{from_url.path} threw exception:  #{e.message}"
          return nil
        end
      end

      # Generic post
      def post(to_url, post_data)
        begin
          http = Net::HTTP.new(to_url.host, to_url.port)
          http.use_ssl = (to_url.scheme == 'https')
          json_post_data = post_data.to_json
          headers = {}
          headers["Content-Length"] = json_post_data.length.to_s
          headers["Content-Type"]   = 'application/json'
          request = Net::HTTP::Post.new(to_url.path, headers)
          request.body= json_post_data
          response = http.start {|h| h.request(request) }
          return response
        rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, OpenSSL::SSL::SSLError,
               Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError => e
          log "Attempt to POST to #{to_url.path} threw exception:  #{e.message}"
          return nil
        end
      end

      # Can we write to the Rails log
      def can_log?
        @can_log ||= (defined?(Rails) && Rails.respond_to?(:logger))
      end

      # Write to log
      def log(str_to_log)
        Rails.logger.info("rack-mauth: " + str_to_log) if can_log?
      end
      
    end
end
