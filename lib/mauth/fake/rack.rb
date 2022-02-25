# frozen_string_literal: true

require 'mauth/rack'

module MAuth
  module Rack
    # This middleware bypasses actual authentication (it does not invoke mauth_client.authentic?).  It
    # instead uses a class attr method (is_authenic?) to determine if the request should be deemed authentic or not.
    # Requests are authentic by default and RequestAuthenticationFaker.authentic = false must be called
    # BEFORE EACH REQUEST in order to make a request inauthentic.
    #
    # This is for testing environments where you do not wish to rely on a mauth service for making requests.
    #
    # Note that if your application does not use env['mauth.app_uuid'] or env['mauth.authentic'] then it
    # may be simpler to simply omit the request authentication middleware entirely in your test environment
    # (rather than switching to this fake one), as all this does is add those keys to the request env.
    class RequestAuthenticationFaker < MAuth::Rack::RequestAuthenticator
      class << self
        def is_authentic? # rubocop:disable Naming/PredicateName
          @is_authentic.nil? ? true : @is_authentic
        end

        def authentic=(is_auth = true) # rubocop:disable Style/OptionalBooleanParameter
          @is_authentic = is_auth
        end
      end

      def call(env)
        retval = if should_authenticate?(env)
                   mauth_request = MAuth::Rack::Request.new(env)
                   env['mauth.protocol_version'] = mauth_request.protocol_version

                   if self.class.is_authentic?
                     @app.call(env.merge!('mauth.app_uuid' => mauth_request.signature_app_uuid,
                       'mauth.authentic' => true))
                   else
                     response_for_inauthentic_request(env)
                   end
                 else
                   @app.call(env)
                 end

        # ensure that the next request is marked authenic unless the consumer of this middleware explicitly deems
        # otherwise
        self.class.authentic = true

        retval
      end
    end
  end
end
