require 'mauth/rack'

module MAuth
  module Rack
    # this middleware bypasses actual authentication (it does not invoke mauth_client.authentic?) and 
    # calls the app, claiming that the request was authenticated. this is for testing environments where 
    # you do not wish to rely on a mauth service for making requests.
    #
    # note that if your application does not use env['mauth.app_uuid'] or env['mauth.authentic'] then it 
    # may be simpler to simply omit the request authentication middleware entirely in your test environment 
    # (rather than switching to this fake one), as all this does is add those keys to the request env. 
    class RequestAuthenticationFaker < MAuth::Rack::RequestAuthenticator
      def call(env)
        if should_authenticate?(env)
          mauth_request = MAuth::Rack::Request.new(env)
          @app.call(env.merge('mauth.app_uuid' => mauth_request.signature_app_uuid, 'mauth.authentic' => true))
        else
          @app.call(env)
        end
      end
    end
  end
end
