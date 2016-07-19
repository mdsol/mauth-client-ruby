require 'mauth/middleware'
require 'mauth/request_and_response'
require 'rack/utils'

module MAuth
  module Rack
    # middleware which will check that a request is authentically signed.
    #
    # if the request is checked and is not authentic, 401 Unauthorized is returned
    # and the app is not called.
    #
    # options accepted (key may be string or symbol)
    # - should_authenticate_check: a proc which should accept a rack env as an argument,
    #   and return true if the request should be authenticated; false if not. if the result
    #   from this is false, the request is passed to the app with no authentication performed.
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

      # discards the body if REQUEST_METHOD is HEAD. sets the Content-Length.
      def handle_head(env)
        status, headers, body = *yield
        headers["Content-Length"] = body.map(&:bytesize).inject(0, &:+).to_s
        [status, headers, env['REQUEST_METHOD'].casecmp('head').zero? ? [] : body]
      end

      # whether the request needs to be authenticated
      def should_authenticate?(env)
        @config['should_authenticate_check'] ? @config['should_authenticate_check'].call(env) : true
      end

      # response when the request is inauthentic. responds with status 401 Unauthorized and a
      # message.
      def response_for_inauthentic_request(env)
        handle_head(env) do
          body = { 'errors' => { 'mauth' => ['Unauthorized'] } }
          [401, { 'Content-Type' => 'application/json' }, [JSON.pretty_generate(body)]]
        end
      end

      # response when the authenticity of the request cannot be determined, due to
      # a problem communicating with the MAuth service. responds with a status of 500 and
      # a message.
      def response_for_unable_to_authenticate(env)
        handle_head(env) do
          body = { 'errors' => { 'mauth' => ['Could not determine request authenticity'] } }
          [500, { 'Content-Type' => 'application/json' }, [JSON.pretty_generate(body)]]
        end
      end
    end

    # same as MAuth::Rack::RequestAuthenticator, but does not authenticate /app_status
    class RequestAuthenticatorNoAppStatus < RequestAuthenticator
      def should_authenticate?(env)
        env['PATH_INFO'] != "/app_status" && super
      end
    end

    # signs outgoing responses
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
          env['rack.input'].rewind
          body = env['rack.input'].read
          env['rack.input'].rewind
          { verb: env['REQUEST_METHOD'], request_url: env['PATH_INFO'], body: body }
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
          @body.each { |part| body << part } # note: rack only requires #each be defined on the body, so not using map or inject
          { status_code: @status.to_i, body: body }
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
