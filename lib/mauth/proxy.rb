require 'mauth/client'
require 'faraday'
require 'rack'

module MAuth
  class Proxy
    def initialize(target_uri, options={})
      @target_uri = target_uri
      @options = options
      options = {:authenticate_responses => true}.merge(options)
      options[:mauth_config] ||= MAuth::Client.default_config
      @connection = ::Faraday.new(target_uri) do |builder|
        builder.use MAuth::Faraday::RequestSigner, options[:mauth_config]
        if options[:authenticate_responses]
          builder.use MAuth::Faraday::ResponseAuthenticator, options[:mauth_config]
        end
        builder.adapter ::Faraday.default_adapter
      end
    end

    def call(request_env)
      request = ::Rack::Request.new(request_env)
      request_method = request_env['REQUEST_METHOD'].downcase.to_sym
      request_env['rack.input'].rewind
      request_body = request_env['rack.input'].read
      request_env['rack.input'].rewind
      request_headers = {}
      request_env.each do |k,v|
        if k =~ /\AHTTP_/ && !%w(HTTP_HOST).include?(k)
          name = $'
          request_headers[name] = v
        end
      end
      response = @connection.run_request(request_method, request.path, request_body, request_headers)
      response_headers = response.headers.reject do |name, value|
        %w(Content-Length Transfer-Encoding).map(&:downcase).include?(name.downcase)
      end
      [response.status, response_headers, [response.body]]
    end
  end
end
