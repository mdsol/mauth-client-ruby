require 'rubygems'
require "bundler/setup"
require 'rack'

simple_app = lambda { |env| [200, "Simple app: success!\n"] }

config = {
  :mauth_baseurl => 'https://mauth-sandbox.imedidata.net',
  :private_key => 'private_key',
  :app_uuid => '1234'
}

$: << 'lib'

require 'rack/mauth'

use Medidata::MAuthMiddleware, config
run simple_app

