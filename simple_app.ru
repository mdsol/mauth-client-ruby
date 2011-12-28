require 'rubygems'
require "bundler/setup"
require 'rack'
require 'rack/mauth'

simple_app = lambda { |env| [200, {'Content-Type' => 'application/json'}, "Simple app: Success!\n"] }

config = {
  :mauth_baseurl => 'https://mauth-sandbox.imedidata.net',
  :version => 'v1'
}

use Medidata::MAuthMiddleware, config
run simple_app

