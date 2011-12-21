require 'json'
require 'base64'
require 'uri'
require 'net/https'
require 'thread'
require 'bundler/setup'
require 'mauth_signer'

module Medidata
  class MAuthMiddleware

    class MissingBaseURL < StandardError; end

    # Middleware initializer
    def initialize(app, config)
      raise MissingBaseURL unless config && config[:mauth_baseurl]

      @app, @mauth_baseurl, @app_uuid, @private_key = app, config[:mauth_baseurl], config[:app_uuid], config[:private_key]
      @path_whitelist, @whitelist_exceptions = config[:path_whitelist], config[:whitelist_exceptions]
      @version = config[:version] || missing_version
      @cached_secrets_mutex = Mutex.new
      @cached_secrets = {}
      @mauth_signer = MAuth::Signer.new(@private_key) if can_authenticate_locally?
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
      # Need to pass in a version of mAuth api to use
      def missing_version
        raise ArgumentError, 'missing api version'
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
        @cached_secrets_mutex.synchronize { yield }
      end

      # Cache for a given token expires every minute
      def token_expired?(token)
        token.nil? || token[:last_refresh] < (Time.now - 60)
      end

      # Find the cached secret for app with given app_uuid
      def secret_for_app(app_uuid)
        sec = fetch_cached_token(app_uuid)
        refresh_token(app_uuid) if token_expired?(sec)

        key = fetch_private_key(app_uuid)
        key.nil? ? log("Cannot find secret for app with uuid #{app_uuid}") : key
      end

      def fetch_cached_token(app_uuid)
        synchronize { @cached_secrets[app_uuid] }
      end

      def fetch_private_key(app_uuid)
        sec = fetch_cached_token(app_uuid)
        synchronize { sec.nil? ? nil : sec[:private_key]}
      end

      # Refresh information for a token from mAuth
      def refresh_token(app_uuid)
        remote_secret = get_remote_secret(app_uuid)
        remote_key_pair = parse_secret(remote_secret) if remote_secret
        synch_cache(remote_key_pair, app_uuid)
      end

      def synch_cache(remote_key_pair, app_uuid)
        synchronize do
          if remote_key_pair.nil?
            @cached_secrets.delete(app_uuid)
          else
            remote_app_uuid = remote_key_pair[app_uuid]
            @cached_secrets[app_uuid] = {}
            @cached_secrets[app_uuid][:private_key] = remote_app_uuid[:private_key]
            @cached_secrets[app_uuid][:last_refresh] = Time.now
          end
        end
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

      def get_remote_secret(app_uuid)
        headers = @mauth_signer.signed_headers(:app_uuid => @app_uuid, :verb => 'GET', :request_url => security_token_path(app_uuid))
        response = get(security_token_url(app_uuid), {:headers => headers})

        return according_to(response, app_uuid)
      end

      # Returns nil when a token should be removed or anything else to add to the cache
      #TODO Call synch_cache directly with an action (ie remove or update) and value(s)
      def according_to(response, app_uuid)
        return mauth_server_error(app_uuid) if response.nil?
        case response.code.to_i
        when 200 then return response.body
        when 404 then return nil
        when 500 then return mauth_server_error(app_uuid)
        else
          log "Attempt to refresh cache with secret from mAuth responded with #{response.code.to_i} #{response.body} for #{app_uuid}"
          return nil
        end
      end

      #return the value inside the cache if remote mAuth responds 500
      def mauth_server_error(app_uuid)
        app_token = fetch_cached_token(app_uuid)
        if app_token.nil?
          log "Couldn't find app_uuid #{app_uuid} in local cache and mAuth returned 500"
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
        @app_uuid && @private_key
      end

      # Is the request authentic?
      def authenticated?(env)
        mws_token, auth_info =  env['HTTP_AUTHORIZATION'].to_s.split(' ')
        app_uuid, digest = auth_info.split(':') if auth_info

        return false unless app_uuid && digest && mws_token == 'MWS'

        params = {
          :app_uuid    => app_uuid,
          :digest      => digest,
          :verb        => env['REQUEST_METHOD'],
          :request_url => env['REQUEST_URI'],
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

      # Rack-mauth does its own authentication
      def authenticate_locally(digest, params)
        secret = secret_for_app(params[:app_uuid])
        secret && MAuth::Signer.new(secret).verify(digest, params)
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

      # Can we write to the Rails log
      def can_log?
        @can_log ||= (defined?(Rails) && Rails.respond_to?(:logger))
      end

      # Write to log
      def log(str_to_log)
        Rails.logger.info("rack-mauth: " + str_to_log) if can_log?
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

    end
end
