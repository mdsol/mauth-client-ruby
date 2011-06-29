require 'rubygems'
require 'rack'


simple_app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, "Hello Rack\n"] }

$: << 'lib'
require 'rack/mauth'
use Medidata::MAuth, 'http://localhost:3001/authentication_tickets.json'
run simple_app

