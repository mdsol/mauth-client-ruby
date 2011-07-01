require 'json'
require 'base64'
require 'uri'
require 'net/https'
require 'thread'
require 'mauth_signer'

module Medidata
  class MAuthMiddleware
    class MissingCacheKey   < Exception; end
    class VerficationFailed < Exception; end

    def initialize(app, config)
      @app, @mauth_baseurl, @app_uuid, @private_key = app, config[:mauth_baseurl], config[:app_uuid], config[:private_key]
      @cached_secrets_mutex = Mutex.new
      @cached_secrets = {}
      @mauth_signer = MAuth::Signer.new(@private_key) if can_authenticate_locally?
    end

    def call(env)
      if should_authenticate?(env)
        authenticated?(env) ? @app.call(env) : unauthenticated_response
      else
        @app.call(env)
      end
    end

    protected
      def authentication_url
        URI.parse(@mauth_baseurl + "/authentication_tickets.json")
      end

      def security_tokens_path
        "/security_tokens.json"
      end

      def security_tokens_url
        URI.parse(@mauth_baseurl + security_tokens_path)
      end

      def synchronize
        @cached_secrets_mutex.synchronize { yield }
      end

      def cache_expired?
        last_refresh = synchronize { @last_refresh }
        last_refresh.nil? || last_refresh < (Time.now - 30)
      end

      def secret_for_app(app_uuid)
        secret = synchronize { @cached_secrets[app_uuid] }
        raise MissingCacheKey if secret.nil?
        secret
      end

      def refresh_cache
        synchronize { @last_refresh = Time.now }
        headers = @mauth_signer.signed_headers(@app_uuid, 'GET', security_tokens_path)

        response = Net::HTTP.start(security_tokens_url.host, security_tokens_url.port) {|http|
          http.get(security_tokens_url.path, headers)
        }
        synchronize do

          @cached_secrets = JSON.parse(response.body).inject({}){|h, token|
            key = token['security_token']['app_uuid']
            val = token['security_token']['private_key']
            h[key] = val
            h
          }
        end
      end

      # Determine if the given endpoint should be authenticated. Perhaps use env['PATH_INFO']
      def should_authenticate?(env)
        # Something like
        #env['PATH_INFO'] =~ /^\/api/
        true
      end

      def can_authenticate_locally?
        @app_uuid && @private_key
      end

      def authenticated?(env)
        mws_token, auth_info =  env['HTTP_AUTHORIZATION'].to_s.split(' ')
        app_uuid, digest = auth_info.split(':') if auth_info

        return false unless app_uuid && digest && mws_token == 'MWS'

        params = {
          :app_uuid    => app_uuid,
          :verb        => env['REQUEST_METHOD'],
          :request_url => env['REQUEST_URI'],
          :time        => env['HTTP_X_MWS_TIME'],
          :post_data   => ''
        }
        if %w(POST PUT).include? env['REQUEST_METHOD']
          params[:post_data] = Base64.encode64(env['rack.input'].read)
          env['rack.input'].rewind
        end

        if can_authenticate_locally?
          authenticate_locally(digest, params)
       else
          authenticate_remotely(digest, params)
        end
      end
      def authenticate_locally(digest, params)
        begin
          secret = secret_for_app(app_uuid)
          if MAuth::Signer.new(secret).verify(digest, params)
           return true
          else
            raise VerficationFailed
          end

        rescue MissingCacheKey, VerficationFailed
          if cache_expired?
            refresh_cache
            retry
          else
            return false
          end
        end
      end

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
        response = Net::HTTP.post_form(authentication_url, 'data' => data.to_json)

        response.code.to_i == 204
      end

      def unauthenticated_response
        [401, {'Content-Type' => 'text/plain'}, 'Unauthorized']
      end

    end
end
