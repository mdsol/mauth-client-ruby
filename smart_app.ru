require 'rubygems'
require 'bundler/setup'
require 'rack'

simple_app = lambda { |env| puts 'Begin'; [200, {'Content-Type' => 'application/json'}, "Smart app: Success!\n"] }

config = {
  :mauth_baseurl => 'https://mauth-sandbox.imedidata.net',
  :private_key => "8CJFmJAS7tHEym8j/n+DWXqRT3QAm/elcsLisNQR4TTfUuzDY8MzcmgmM5ab8+ZzLN1cDKCnrfYS5mX2omyC1A==",
  :app_uuid => 'G'
}

require 'rack/mauth'

use Medidata::MAuthMiddleware, config
run simple_app
