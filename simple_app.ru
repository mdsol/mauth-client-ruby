require 'rubygems'
require "bundler/setup"
require 'rack'
require 'mauth_signer'
require 'rack/mauth'

simple_app = lambda { |env| puts 'Begin'; [200, {'Content-Type' => 'application/json'}, "Simple app: Success!\n"] }

config = {
  :mauth_baseurl => 'https://mauth-sandbox.imedidata.net',
  #:private_key => 'QpeIisdvU9AJC15wkLf83xDPiCFaTL6r8iQY56nZqaqp0yTfJVKAgtOqdGyAOyVDd9b2Uz8ZukiyXR5H56JLEg==',
  #:app_uuid => '91111111-1111-1111-1111-111111111111',
  :version => 'v1'
}

use Medidata::MAuthMiddleware, config
run simple_app

