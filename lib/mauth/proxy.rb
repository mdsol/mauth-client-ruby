require 'mauth/client'
require 'faraday'
require 'rack'

module MAuth
  # MAuth::Proxy is a simple Rack application to take incoming requests, sign them with MAuth, and 
  # proxy them to a target URI. the responses from the target may be authenticated, with MAuth 
  # (and are by default).
  class Proxy
    # target_uri is the base relative to which requests are made. 
    #
    # options:
    # - :authenticate_responses - boolean, default true. whether responses will be authenticated. 
    #   if this is true and an inauthentic response is encountered, then MAuth::InauthenticError 
    #   will be raised.
    # - :mauth_config - configuration passed to MAuth::Client.new (see its doc). default is 
    #   MAuth::Client.default_config
    def initialize(target_uri, options={})
      @target_uris = target_uri
      @browser_proxy = options.delete(:browser_proxy)
      @options = options
      options = {:authenticate_responses => true}.merge(options)
      options[:mauth_config] ||= MAuth::Client.default_config
      if @browser_proxy # Browser proxy mode
        @signer_connection = ::Faraday.new(nil) do |builder|
          builder.use MAuth::Faraday::RequestSigner, options[:mauth_config]
          if options[:authenticate_responses]
            builder.use MAuth::Faraday::ResponseAuthenticator, options[:mauth_config]
          end
          builder.adapter ::Faraday.default_adapter
        end
        @unsigned_connection = ::Faraday.new(nil) do |builder|
          builder.adapter ::Faraday.default_adapter
        end
      else # hard-wired mode
        @connection = ::Faraday.new(target_uri) do |builder|
                builder.use MAuth::Faraday::RequestSigner, options[:mauth_config]
                if options[:authenticate_responses]
                  builder.use MAuth::Faraday::ResponseAuthenticator, options[:mauth_config]
                end
                builder.adapter ::Faraday.default_adapter
        end
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

      if @browser_proxy
        target_uri = request_env["REQUEST_URI"]

        unsigned_request = @target_uris.select {|u| target_uri.start_with? u}.empty?
        if unsigned_request
          connection = @unsigned_connection
        else
          connection = @signer_connection
        end
        response = connection.run_request(request_method, target_uri, request_body, request_headers)
      else
        response = @connection.run_request(request_method, request.fullpath, request_body, request_headers)
      end
      response_headers = response.headers.reject do |name, value|
        %w(Content-Length Transfer-Encoding).map(&:downcase).include?(name.downcase)
      end
      [response.status, response_headers, [response.body || ""]]
    end
  end
end
