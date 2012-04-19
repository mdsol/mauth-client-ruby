require 'mauth/middleware'
require 'mauth/request_and_response'

module MAuth
  module Rack
    class RequestAuthenticator < MAuth::Middleware
      def call(env)
        if should_authenticate?(env)
          mauth_request = MAuth::Rack::Request.new(env)
          begin
            if mauth_client.authentic?(mauth_request)
              @app.call(env.merge('mauth.app_uuid' => mauth_request.signature_app_uuid, 'mauth.authentic' => true))
            else
              response_for_inauthentic_request(env)
            end
          rescue MAuth::UnableToAuthenticateError
            response_for_unable_to_authenticate(env)
          end
        else
          @app.call(env)
        end
      end
      def should_authenticate?(env)
        @config['should_authenticate_check'] ? @config['should_authenticate_check'].call(env) : true
      end
      def response_for_inauthentic_request(env)
        [401, {'Content-Type' => 'text/plain'}, ['Unauthorized']]
      end
      def response_for_unable_to_authenticate(env)
        [500, {'Content-Type' => 'text/plain'}, ['Could not determine request authenticity']]
      end
    end
    class ResponseSigner < MAuth::Middleware
      def call(env)
        unsigned_response = @app.call(env)
        signed_response = mauth_client.signed(MAuth::Rack::Response.new(*unsigned_response))
        signed_response.status_headers_body
      end
    end

    # representation of a request composed from a rack request env which can be passed to a 
    # Mauth::Client for authentication 
    class Request < MAuth::Request
      include Signed
      attr_reader :env
      def initialize(env)
        @env = env
      end
      def attributes_for_signing
        @attributes_for_signing ||= begin
          body = nil
          if %w(POST PUT).include?(env['REQUEST_METHOD'])
            env['rack.input'].rewind
            body = env['rack.input'].read
            env['rack.input'].rewind
          end
          {:verb => env['REQUEST_METHOD'], :request_url => env['PATH_INFO'], :body => body}
        end
      end
      def x_mws_time
        @env['HTTP_X_MWS_TIME']
      end
      def x_mws_authentication
        @env['HTTP_X_MWS_AUTHENTICATION']
      end
    end

    # representation of a response composed from a rack response (status, headers, body) which 
    # can be passed to a Mauth::Client for signing 
    class Response < MAuth::Response
      def initialize(status, headers, body)
        @status = status
        @headers = headers
        @body = body
      end
      def status_headers_body
        [@status, @headers, @body]
      end
      def attributes_for_signing
        @attributes_for_signing ||= begin
          body = ''
          @body.each {|part| body << part } # note: rack only requires #each be defined on the body, so not using map or inject 
          {:status_code => @status.to_i, :body => body}
        end
      end
      # takes a Hash of headers; returns an instance of this class whose 
      # headers have been updated with the argument headers
      def merge_headers(headers)
        self.class.new(@status, @headers.merge(headers), @body)
      end
    end
  end
end
