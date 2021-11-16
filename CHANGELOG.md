## v6.4.0
- Support Ruby 3.1.
- Allow Faraday 2.x.

## v6.3.0
- Support Ruby 3.0.
- Drop support for Ruby < 2.5.0.

## v6.2.1
- Fix SecurityTokenCacher to not cache tokens forever.

## v6.2.0
- Drop legacy security token expiry in favor of honoring server cache headers via Faraday HTTP Cache Middleware.

## v6.1.1
- Replace `URI.escape` with `CGI.escape` in SecurityTokenCacher to suppress "URI.escape is obsolete" warning.

## v6.1.0
- Allow Faraday 1.x.

## v6.0.0
- Added parsing code to test with mauth-protocol-test-suite.
- Added unescape step in query_string encoding in order to remove 'double encoding'.
- Added normalization of paths.
- Added flag to sign only with V1.
- Changed V2 to V1 fallback to be configurable.
- Fixed bug in sorting query parameters.

## v5.1.0
- Fall back to V1 when V2 authentication fails.

## v5.0.2
- Fix to not raise FrozenError when string to sign contains frozen value.

## v5.0.1
- Update euresource escaping of query string.

## v5.0.0
- Add support for MWSV2 protocol.
- Change request signing to sign with both V1 and V2 protocols by default.
- Update log message for authentication request to include protocol version used.
- Added `benchmark` rake task to benchmark request signing and authentication.

## v4.1.1
- Use warning level instead of error level for logs about missing mauth header.

## v4.1.0
- Drop support for Ruby < 2.3.0
- Update development dependencies

## v4.0.4
- Restore original behavior in the proxy of forwarding of headers that begin with HTTP_ (except for HTTP_HOST) but removing the HTTP_.

## v4.0.3
- Updated signature to decode number sign (#) in requests

## v4.0.2
- Store the config data to not load the config file multiple times

## v4.0.1
- Open source and publish this gem on rubygems.org, no functionality changes

## v4.0.0
- *yanked*

## v3.1.4
- Use String#bytesize method instead of Rack::Utils' one, which was removed in Rack 2.0

## v3.1.3
- Increased the default timeout when fetching keys from MAuth from 1 second to 10 seconds
- Properly honor faraday_options: timeout in mauth.yml for faraday < 0.9

## v3.1.2
- Fixed bug in Faraday call, not to raise exception when adding authenticate information to response.

## v3.1.1
- Properly require version file. Solves exception with the Faraday middleware.

## v3.1.0
- Updated `mauth.rb.dice` template to use `MAuth::Client.default_config` method and store the config in `MAUTH_CONF` constant

## v3.0.2
- Always pass a private key to the `ensure_is_private_key` method

## v3.0.1
- Use `ensure_is_private_key` in the `mauth_key` template

## v3.0.0
- Drop support for ruby 1.x

## v2.9.0
- Add a dice template for mauth initializer

## 2-8-stable
- Added an ssl_certs_path option to support JRuby applications
- Updated dice templates to ensure `rake config` raises an error in production env if required variables are missing.

## v2.7.2
- Added logging of mauth app_uuid of requester and requestee on each request

## v2.7.0
- Ability to pass custom headers into mauth-client and mauth-proxy
- Upgraded to use newest version of Faraday Middleware
- Faraday_options now only get merged to the request (previously got merged into everything)
- Syntax highlighting in hale+json output

## v2.6.4
- Less restrictive rack versioning to allow for more consumers.
- Allow verification even if intermediate web servers unescape URLs.

## v2.6.3
- Fixed bug where nil Rails.logger prevented a logger from being built.

## v2.6.2
- Added templates for dice_bag, now rake config:generate_all will create mauth config files when you include this gem.

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
- MAuth::Rack::RequestAuthenticator middleware responds with json (instead of text/plain) for inauthentic requests and requests which it is unable to authenticate
- Added MAuth::Client.default_config method
- Added mauth-proxy executable
- Faraday middlewares are registered with Faraday
- Rack middleware correctly handles Content-Length with HEAD requests
- MAuth::Client raises MAuth::Client::ConfigurationError instead of ArgumentError or RuntimeError as appropriate

## v2.4.0
- Colorized output from the mauth-client CLI
- Add --content-type option to CLI
- CLI rescues and prints MAuth errors instead of them bubbling up to the interpreter
- Improved method documentation
- Fix default null logger on windows where /dev/null is not available
- Improve error logging

## v2.3.0
- When authentication headers are missing, the previous message ("No x-mws-time present") is replaced by the somewhat more informative "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank."
- More informative help messages from mauth-client CLI
- CLI sets a user-agent
- Handling timeout errors is fixed (previously only handled connection errors)
- Middleware MAuth::Rack::RequestAuthenticationFaker for testing
- More and better specs

## v2.2.0
- Fixes an issue where requests which have a body and are not PUT or POST were not being correctly signed in rack middleware
- Improves the CLI, adding command-line options --[no-]authenticate to decide whether to authenticate responses, and --[no-]verbose to decide whether to dump the entire request and response, or just the response body. and --help to
  Remind you.
- Fixes mauth-client CLI being registered as an executable in the gemspec - now it should be possible to just `bundle exec mauth-client` if you have the gem bundle installed (or just `mauth-client` if you have it installed as a regular gem, but that's less straightforward)
- New middleware MAuth::Rack::RequestAuthenticatorNoAppStatus - same as MAuth::Rack::RequestAuthenticator, but does not authenticate /app_status. this will be the most commonly used case, so made it its own middleware.
- Middleware responds to HEAD requests correctly in error conditions, not including a response body
- Drops backports dependency (Ben has found some issues with this gem, and it was easier to drop the depedency entirely than figure out whether these issues affected mauth-client and if it could be fixed)
- Fix issue with remote authentication against the currently-deployed mauth service with a request signed by a nonexistent app_uuid

## v2.1.1
- Fix an issue in a case where the rack.input is not rewound before mauth-client attempts to read it

## v2.1.0
- MAuth::Client handles the :private_key_file, so you can remove from your application the bit that does that - this bit can be deleted:
```
if mauth_conf['private_key_file']
  mauth_conf['private_key'] = File.read(mauth_conf['private_key_file'])
end
```

- Autoloads are in place so that once you require 'mauth/client', you should not need to require mauth/rack, mauth/faraday, or mauth/request_and_response.

## v2.0.0
- Rewrite combining the mauth_signer and rack-mauth gems
