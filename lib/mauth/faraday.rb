require 'faraday/middleware'

module MAuth
  module Faraday
    class RequestSigner < ::Faraday::Middleware
      def initialize(app, app_uuid, mauth_signer_config)
        @app = app
        @app_uuid = app_uuid
        @mauth_signer = MAuth::Signer.new(mauth_signer_config)
      end
      def call(env)
        mauth_params = {:verb => env[:method].to_s.upcase, :request_url => env[:url].path, :body => env[:body], :app_uuid => @app_uuid}
        env[:request_headers].update(@mauth_signer.signed_request_headers(mauth_params))
        @app.call(env)
      end
    end
  end
end
