require 'mauth/middleware'
require 'mauth/request_and_response'

Faraday::Request.register_middleware(mauth_request_signer: proc { MAuth::Faraday::RequestSigner })
Faraday::Response.register_middleware(mauth_response_authenticator: proc { MAuth::Faraday::ResponseAuthenticator })

module MAuth
  module Faraday
    # faraday middleware to sign outgoing requests
    class RequestSigner < MAuth::Middleware
      def call(request_env)
        signed_request_env = mauth_client.signed(MAuth::Faraday::Request.new(request_env)).request_env
        @app.call(signed_request_env)
      end
    end

    # faraday middleware to authenticate incoming responses
    class ResponseAuthenticator < MAuth::Middleware
      def call(request_env)
        @app.call(request_env).on_complete do |response_env|
          mauth_response = MAuth::Faraday::Response.new(response_env)
          mauth_client.authenticate!(mauth_response) # raises MAuth::InauthenticError when inauthentic
          response_env['mauth.app_uuid'] = mauth_response.signature_app_uuid
          response_env['mauth.authentic'] = true
          response_env
        end
      end
    end

    # representation of a request (outgoing) composed from a Faraday request env which can be
    # passed to a Mauth::Client for signing
    class Request < MAuth::Request
      attr_reader :request_env
      def initialize(request_env)
        @request_env = request_env
      end

      def attributes_for_signing
        @attributes_for_signing ||= begin
          request_url = request_url.empty? ? '/' : @request_env[:url].path
          {
            verb: @request_env[:method].to_s.upcase,
            request_url: request_url,
            body: @request_env[:body],
            query_string: @request_env[:url].query
          }
        end
      end

      # takes a Hash of headers; returns an instance of this class whose
      # headers have been merged with the argument headers
      def merge_headers(headers)
        self.class.new(@request_env.merge(request_headers: @request_env[:request_headers].merge(headers)))
      end
    end

    # representation of a Response (incoming) composed from a Faraday response env which can be
    # passed to a Mauth::Client for authentication
    class Response < MAuth::Response
      include Signed
      attr_reader :response_env
      def initialize(response_env)
        @response_env = response_env
      end

      def attributes_for_signing
        @attributes_for_signing ||= { status_code: response_env[:status], body: response_env[:body] }
      end

      def x_mws_time
        @response_env[:response_headers]['x-mws-time']
      end

      def x_mws_authentication
        @response_env[:response_headers]['x-mws-authentication']
      end

      def mcc_time
        @response_env[:response_headers]['mcc-time']
      end

      def mcc_authentication
        @response_env[:response_headers]['mcc-authentication']
      end
    end

    # add MAuth-Client's user-agent to a request
    class MAuthClientUserAgent
      def initialize(app, agent_base = "Mauth-Client")
        @app = app
        @agent_base = agent_base
      end

      def call(request_env)
        agent = "#{@agent_base} (MAuth-Client: #{MAuth::VERSION}; Ruby: #{RUBY_VERSION}; platform: #{RUBY_PLATFORM})"
        request_env[:request_headers]['User-Agent'] ||= agent
        @app.call(request_env)
      end
    end
  end
end
