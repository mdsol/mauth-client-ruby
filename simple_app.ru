require 'rubygems'
require "bundler/setup"
require 'rack'
require 'rack/mauth'

simple_app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, ["Simple app: Success!\n"]] }

config = {
  :mauth_baseurl => 'http://0.0.0.0:3000',
  :mauth_api_version => 'v1'
}
require 'logger'
config[:logger] = Logger.new(STDERR)

use MAuth::Rack::RequestAuthenticator, config
run simple_app
