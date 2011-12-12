require 'json'
require 'base64'
require 'uri'
require 'net/https'
require 'thread'
require 'mauth_signer'

module Medidata
  class MAuthMiddleware
    
    class MissingBaseURL < StandardError; end

    # Middleware initializer
    def initialize(app, config)
      raise MissingBaseURL unless config && config[:mauth_baseurl]
      
      @app, @mauth_baseurl, @app_uuid, @private_key = app, config[:mauth_baseurl], config[:app_uuid], config[:private_key]
      @path_whitelist, @whitelist_exceptions = config[:path_whitelist], config[:whitelist_exceptions]
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
      # URL to which authenication tickets are posted for the purpose of remote authentication with mAuth
      def authentication_url
        URI.parse(@mauth_baseurl + "/authentication_tickets.json")
      end

      # Path to security tokens in mAuth
      def security_tokens_path
        "/security_tokens.json"
      end

      # URL for security tokens
      def security_tokens_url
        URI.parse(@mauth_baseurl + security_tokens_path)
      end

      # Synchronize ivars
      def synchronize
        @cached_secrets_mutex.synchronize { yield }
      end

      # Cache expires every minute
      def cache_expired?
        last_refresh = synchronize { @last_refresh }
        last_refresh.nil? || last_refresh < (Time.now - 60)
      end

      # Find the cached secret for app with given app_uuid
      def secret_for_app(app_uuid)
        refresh_cache if cache_expired?
        sec = synchronize { @cached_secrets[app_uuid] }
        log "Cannot find secret for app with uuid #{app_uuid}" unless sec
        sec
      end

      # Get new shared secrets from mAuth
      def refresh_cache        
        log "Refreshing private_key cache"

        synchronize { @last_refresh = Time.now }
        remote_secrets = get_remote_secrets
        new_cache = parse_secrets(remote_secrets) if remote_secrets
        synchronize { @cached_secrets = new_cache if new_cache}
      end

      # Parse secrets from mAuth
      def parse_secrets(secrets_from_mauth)
        begin
          new_cache = JSON.parse(secrets_from_mauth).inject({}){|h, token|
            key = token['security_token']['app_uuid']
            val = token['security_token']['private_key']
            h[key] = val
            h
          }
        rescue JSON::ParserError, TypeError
          log "Cannot parse JSON response for shared secret request from mAuth:  #{secrets_from_mauth}"
        end
      end
      
      # Get secrets from mAuth
      def get_remote_secrets
        headers = @mauth_signer.signed_headers(:app_uuid => @app_uuid, :verb => 'GET', :request_url => security_tokens_path)
        response = get(security_tokens_url, {:headers => headers})
        
        return nil unless response
        if response.code.to_i == 200
          return response.body
        else
          log "Attempt to refresh cache with secrets from mAuth responded with #{response.code} #{response.body}"
          return nil
        end
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
        response = post(authentication_url, 'data' => data.to_json)
        
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
          request = options[:headers] ? Net::HTTP::Get.new(from_url.path, options[:headers]) : Net::HTTP::Get.new(from_url.path)
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
          request = Net::HTTP::Post.new(to_url.path)
          request.set_form_data(post_data)
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
