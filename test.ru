require 'rubygems'
require 'rack'

private_key = "secret"

simple_app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, "Hello Rack\n"] }

config = {
  :mauth_baseurl => 'http://localhost:3001',

  # NB: private_key and app_uuid enable local authentication.
  # They'll only work if the app_uuid can request private keys in MAuth.
  # Authentication won't work if they're provided and the app doesn't have permission in MAuth to request private keys
  :private_key => private_key,
  :app_uuid => '1234'
}

$: << 'lib'
require 'rack/mauth'

require 'ruby-debug'

#config = { :mauth_baseurl => 'http://localhost:3001'}
use Medidata::MAuthMiddleware, config
run simple_app

