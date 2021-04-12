require 'mauth/client'
require 'faraday'
require 'rack'

module Mauth
  # Mauth::Proxy is a simple Rack application to take incoming requests, sign them with Mauth, and
  # proxy them to a target URI. the responses from the target may be authenticated, with Mauth
  # (and are by default).
  class Proxy
    # target_uri is the base relative to which requests are made.
    #
    # options:
    # - :authenticate_responses - boolean, default true. whether responses will be authenticated.
    #   if this is true and an inauthentic response is encountered, then Mauth::InauthenticError
    #   will be raised.
    # - :mauth_config - configuration passed to Mauth::Client.new (see its doc). default is
    #   Mauth::Client.default_config
    def initialize(target_uri, options = {})
      @target_uris = target_uri
      @browser_proxy = options.delete(:browser_proxy)
      @options = options
      options = { authenticate_responses: true }.merge(options)
      options[:mauth_config] ||= Mauth::Client.default_config
      if @browser_proxy # Browser proxy mode
        @signer_connection = ::Faraday.new do |builder|
          builder.use Mauth::Faraday::RequestSigner, options[:mauth_config]
          builder.use Mauth::Faraday::ResponseAuthenticator, options[:mauth_config] if options[:authenticate_responses]
          builder.adapter ::Faraday.default_adapter
        end
        @unsigned_connection = ::Faraday.new do |builder|
          builder.adapter ::Faraday.default_adapter
        end
      else # hard-wired mode
        @connection = ::Faraday.new(target_uri) do |builder|
          builder.use Mauth::Faraday::RequestSigner, options[:mauth_config]
          builder.use Mauth::Faraday::ResponseAuthenticator, options[:mauth_config] if options[:authenticate_responses]
          builder.adapter ::Faraday.default_adapter
        end
      end
      @persistent_headers = {}
      if options[:headers]
        options[:headers].each do |cur|
          raise "Headers must be in the format of [key]:[value]" unless cur.include?(':')
          key, throw_away, value = cur.partition(':')
          @persistent_headers[key.strip] = value.strip
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
      request_env.each do |k, v|
        if k.start_with?('HTTP_') && k != 'HTTP_HOST'
          name = k.sub(/\AHTTP_/, '')
          request_headers[name] = v
        end
      end
      request_headers.merge!(@persistent_headers)
      if @browser_proxy
        target_uri = request_env["REQUEST_URI"]
        connection = @target_uris.any? { |u| target_uri.start_with? u } ? @signer_connection : @unsigned_connection
        response = connection.run_request(request_method, target_uri, request_body, request_headers)
      else
        response = @connection.run_request(request_method, request.fullpath, request_body, request_headers)
      end
      response_headers = response.headers.reject do |name, _value|
        %w(Content-Length Transfer-Encoding).map(&:downcase).include?(name.downcase)
      end
      [response.status, response_headers, [response.body || '']]
    end
  end
end
