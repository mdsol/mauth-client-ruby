require 'json'
require 'base64'
require 'uri'
require 'net/https'

module Medidata
  class MAuth
    def initialize(app, mauth_endpoint)
      @app, @mauth_endpoint = app, URI.parse(mauth_endpoint)
    end

    def call(env)
      if should_authenticate?(env)
        authenticated?(env) ? @app.call(env) : unauthenticated_response
      else
        @app.call(env)
      end
    end

    # Determine if the given endpoint should be authenticated. Perhaps use env['PATH_INFO']
    def should_authenticate?(env)
      true
    end

    def authenticated?(env)
      mws_token, auth_info =  env['HTTP_AUTHORIZATION'].to_s.split(' ')
      app_uuid, digest = auth_info.split(':') if auth_info

      return false unless app_uuid && digest && mws_token == 'MWS'

      data = {
        'verb' => env['REQUEST_METHOD'],
        'app_uuid' => app_uuid,
        'client_signature' => digest,
        'request_url' => env['HTTP_HOST'] + env['REQUEST_URI'],
        'request_time' => env['HTTP_X_MWS_TIME']
      }
      if env['REQUEST_METHOD'] == 'POST'
        data['b64encoded_post_data'] = Base64.encode64(env['rack.input'].read)
        env['rack.input'].rewind
      end


      # Post to endpoint
      response = Net::HTTP.post_form(@mauth_endpoint, 'data' => data.to_json)

      response.code.to_i == 204
    end

    def unauthenticated_response
      [401, {'Content-Type' => 'text/plain'}, 'Unauthorized']
    end

  end
end
