# MAuth-Client History
## v2.7.0
- ability to pass custom headers into mauth-client and mauth-proxy
- Upgraded to use newest version of Faraday Middleware
- faraday_options now only get merged to the request (previously got merged into everything)
- syntax highlighting in hale+json output

## v2.6.4

- Less restrictive rack versioning to allow for more consumers.
- Allow verification even if intermediate web servers unescape URLs.

## v2.6.3

- Fixed bug where nil Rails.logger prevented a logger from being built.

## v2.6.2

- Added templates for dice_bag, now rake config:generate_all will create
  mauth config files when you include this gem.

## v2.6.1

- Imported documentation from Medinet into the project's doc directory 
- Add Shamus

## v2.6.0

- CLI option --no-ssl-verify disables SSL verification
- Syntax highlighting with CodeRay colorizes request and response bodies of recognized media types
- MAuth::Proxy class now lives in lib, in mauth/proxy, and may be used as a rack application
- mauth-proxy executable recognizes --no-authenticate option for responses
- MAuth::Proxy bugfix usage of REQUEST_URI; use Rack::Request#fullpath instead

## v2.5.0

- MAuth::Rack::RequestAuthenticator middleware responds with json (instead of text/plain) for inauthentic requests 
  and requests which it is unable to authenticate
- added MAuth::Client.default_config method
- added mauth-proxy executable
- Faraday middlewares are registered with Faraday
- Rack middleware correctly handles Content-Length with HEAD requests
- MAuth::Client raises MAuth::Client::ConfigurationError instead of ArgumentError or RuntimeError as appropriate

## v2.4.0

- colorized output from the mauth-client CLI 
- add --content-type option to CLI
- CLI rescues and prints MAuth errors instead of them bubbling up to the interpreter
- improved method documentation 
- fix default null logger on windows where /dev/null is not available 
- improve error logging

## v2.3.0

- when authentication headers are missing, the previous message ("No x-mws-time present") is replaced by the somewhat 
  more informative "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank."
- more informative help messages from mauth-client CLI
- CLI sets a user-agent 
- handling timeout errors is fixed (previously only handled connection errors)
- middleware MAuth::Rack::RequestAuthenticationFaker for testing 
- more and better specs 

## v2.2.0

- fixes an issue where requests which have a body and are not PUT or POST were not being correctly signed in rack 
  middleware 
- improves the CLI, adding command-line options --[no-]authenticate to decide whether to authenticate responses, and 
  --[no-]verbose to decide whether to dump the entire request and response, or just the response body. and --help to 
  remind you. 
- fixes mauth-client CLI being registered as an executable in the gemspec - now it should be possible to just 
  `bundle exec mauth-client` if you have the gem bundle installed (or just `mauth-client` if you have it installed as 
  a regular gem, but that's less straightforward) 
- new middleware MAuth::Rack::RequestAuthenticatorNoAppStatus - same as MAuth::Rack::RequestAuthenticator, but does 
  not authenticate /app_status. this will be the most commonly used case, so made it its own middleware. 
- middleware responds to HEAD requests correctly in error conditions, not including a response body 
- drops backports dependency (Ben has found some issues with this gem, and it was easier to drop the depedency 
  entirely than figure out whether these issues affected mauth-client and if it could be fixed) 
- fix issue with remote authentication against the currently-deployed mauth service with a request signed by a 
  nonexistent app_uuid

## v2.1.1

- fix an issue in a case where the rack.input is not rewound before mauth-client attempts to read it

## v2.1.0

- MAuth::Client handles the :private_key_file, so you can remove from your application the bit that does that - this 
  bit can be deleted:

<pre>
if mauth_conf['private_key_file']
  mauth_conf['private_key'] = File.read(mauth_conf['private_key_file'])
end
</pre>

- autoloads are in place so that once you require 'mauth/client', you should not need to require mauth/rack, 
  mauth/faraday, or mauth/request_and_response.

## v2.0.0

- Rewrite combining the mauth_signer and rack-mauth gems 
