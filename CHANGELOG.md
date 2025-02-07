# Changelog

## [7.3.0](https://github.com/mdsol/mauth-client-ruby/compare/v7.2.0...v7.3.0) (2025-01-16)


### Features

* Support ruby 3.4 ([97f0f32](https://github.com/mdsol/mauth-client-ruby/commit/97f0f3211d5da8c92fc0ab6bbf44c6ad6929c807))

## [7.2.0](https://github.com/mdsol/mauth-client-ruby/compare/v7.1.0...v7.2.0) (2024-04-25)


### Features

* Support Ruby 3.3 ([245bb06](https://github.com/mdsol/mauth-client-ruby/commit/245bb06d8abb86bd6a4b557b84bc9d0898254a95))

## 7.1.0
- Add MAuth::PrivateKeyHelper.load method to process RSA private keys.
- Update Faraday configuration in SecurityTokenCacher:
  - Add the `MAUTH_USE_RAILS_CACHE` environment variable to make `Rails.cache` usable to cache public keys.
  - Shorten timeout for connection, add retries, and use persistent HTTP connections.
- Drop support for Faraday < 1.9.

## 7.0.0
- Remove dice_bag and set configuration through environment variables directly.
- Rename the `V2_ONLY_SIGN_REQUESTS`, `V2_ONLY_AUTHENTICATE`, `DISABLE_FALLBACK_TO_V1_ON_V2_FAILURE` and `V1_ONLY_SIGN_REQUESTS` environment variables.
- Remove the remote authenticator.
- Support Ruby 3.2.

See [UPGRADE_GUIDE.md](UPGRADE_GUIDE.md#upgrading-to-700) for migration.

## 6.4.3
- Force Rack > 2.2.3 to resolve [CVE-2022-30123](https://github.com/advisories/GHSA-wq4h-7r42-5hrr).

## 6.4.2
- Add MAuth::ServerHelper module with convenience methods for servers to access requester app uuid.

## 6.4.1
- Fix MAuth::Rack::Response to not raise FrozenError.

## 6.4.0
- Support Ruby 3.1.
- Drop support for Ruby < 2.6.0.
- Allow Faraday 2.x.

## 6.3.0
- Support Ruby 3.0.
- Drop support for Ruby < 2.5.0.

## 6.2.1
- Fix SecurityTokenCacher to not cache tokens forever.

## 6.2.0
- Drop legacy security token expiry in favor of honoring server cache headers via Faraday HTTP Cache Middleware.

## 6.1.1
- Replace `URI.escape` with `CGI.escape` in SecurityTokenCacher to suppress "URI.escape is obsolete" warning.

## 6.1.0
- Allow Faraday 1.x.

## 6.0.0
- Added parsing code to test with mauth-protocol-test-suite.
- Added unescape step in query_string encoding in order to remove 'double encoding'.
- Added normalization of paths.
- Added flag to sign only with V1.
- Changed V2 to V1 fallback to be configurable.
- Fixed bug in sorting query parameters.

## 5.1.0
- Fall back to V1 when V2 authentication fails.

## 5.0.2
- Fix to not raise FrozenError when string to sign contains frozen value.

## 5.0.1
- Update euresource escaping of query string.

## 5.0.0
- Add support for MWSV2 protocol.
- Change request signing to sign with both V1 and V2 protocols by default.
- Update log message for authentication request to include protocol version used.
- Added `benchmark` rake task to benchmark request signing and authentication.

## 4.1.1
- Use warning level instead of error level for logs about missing mauth header.

## 4.1.0
- Drop support for Ruby < 2.3.0
- Update development dependencies

## 4.0.4
- Restore original behavior in the proxy of forwarding of headers that begin with HTTP_ (except for HTTP_HOST) but removing the HTTP_.

## 4.0.3
- Updated signature to decode number sign (#) in requests

## 4.0.2
- Store the config data to not load the config file multiple times

## 4.0.1
- Open source and publish this gem on rubygems.org, no functionality changes

## 4.0.0
- *yanked*

## 3.1.4
- Use String#bytesize method instead of Rack::Utils' one, which was removed in Rack 2.0

## 3.1.3
- Increased the default timeout when fetching keys from MAuth from 1 second to 10 seconds
- Properly honor faraday_options: timeout in mauth.yml for faraday < 0.9

## 3.1.2
- Fixed bug in Faraday call, not to raise exception when adding authenticate information to response.

## 3.1.1
- Properly require version file. Solves exception with the Faraday middleware.

## 3.1.0
- Updated `mauth.rb.dice` template to use `MAuth::Client.default_config` method and store the config in `MAUTH_CONF` constant

## 3.0.2
- Always pass a private key to the `ensure_is_private_key` method

## 3.0.1
- Use `ensure_is_private_key` in the `mauth_key` template

## 3.0.0
- Drop support for ruby 1.x

## 2.9.0
- Add a dice template for mauth initializer

## 2-8-stable
- Added an ssl_certs_path option to support JRuby applications
- Updated dice templates to ensure `rake config` raises an error in production env if required variables are missing.

## 2.7.2
- Added logging of mauth app_uuid of requester and requestee on each request

## 2.7.0
- Ability to pass custom headers into mauth-client and mauth-proxy
- Upgraded to use newest version of Faraday Middleware
- Faraday_options now only get merged to the request (previously got merged into everything)
- Syntax highlighting in hale+json output

## 2.6.4
- Less restrictive rack versioning to allow for more consumers.
- Allow verification even if intermediate web servers unescape URLs.

## 2.6.3
- Fixed bug where nil Rails.logger prevented a logger from being built.

## 2.6.2
- Added templates for dice_bag, now rake config:generate_all will create mauth config files when you include this gem.

## 2.6.1
- Imported documentation from Medinet into the project's doc directory
- Add Shamus

## 2.6.0
- CLI option --no-ssl-verify disables SSL verification
- Syntax highlighting with CodeRay colorizes request and response bodies of recognized media types
- MAuth::Proxy class now lives in lib, in mauth/proxy, and may be used as a rack application
- mauth-proxy executable recognizes --no-authenticate option for responses
- MAuth::Proxy bugfix usage of REQUEST_URI; use Rack::Request#fullpath instead

## 2.5.0
- MAuth::Rack::RequestAuthenticator middleware responds with json (instead of text/plain) for inauthentic requests and requests which it is unable to authenticate
- Added MAuth::Client.default_config method
- Added mauth-proxy executable
- Faraday middlewares are registered with Faraday
- Rack middleware correctly handles Content-Length with HEAD requests
- MAuth::Client raises MAuth::Client::ConfigurationError instead of ArgumentError or RuntimeError as appropriate

## 2.4.0
- Colorized output from the mauth-client CLI
- Add --content-type option to CLI
- CLI rescues and prints MAuth errors instead of them bubbling up to the interpreter
- Improved method documentation
- Fix default null logger on windows where /dev/null is not available
- Improve error logging

## 2.3.0
- When authentication headers are missing, the previous message ("No x-mws-time present") is replaced by the somewhat more informative "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank."
- More informative help messages from mauth-client CLI
- CLI sets a user-agent
- Handling timeout errors is fixed (previously only handled connection errors)
- Middleware MAuth::Rack::RequestAuthenticationFaker for testing
- More and better specs

## 2.2.0
- Fixes an issue where requests which have a body and are not PUT or POST were not being correctly signed in rack middleware
- Improves the CLI, adding command-line options --[no-]authenticate to decide whether to authenticate responses, and --[no-]verbose to decide whether to dump the entire request and response, or just the response body. and --help to
  Remind you.
- Fixes mauth-client CLI being registered as an executable in the gemspec - now it should be possible to just `bundle exec mauth-client` if you have the gem bundle installed (or just `mauth-client` if you have it installed as a regular gem, but that's less straightforward)
- New middleware MAuth::Rack::RequestAuthenticatorNoAppStatus - same as MAuth::Rack::RequestAuthenticator, but does not authenticate /app_status. this will be the most commonly used case, so made it its own middleware.
- Middleware responds to HEAD requests correctly in error conditions, not including a response body
- Drops backports dependency (Ben has found some issues with this gem, and it was easier to drop the depedency entirely than figure out whether these issues affected mauth-client and if it could be fixed)
- Fix issue with remote authentication against the currently-deployed mauth service with a request signed by a nonexistent app_uuid

## 2.1.1
- Fix an issue in a case where the rack.input is not rewound before mauth-client attempts to read it

## 2.1.0
- MAuth::Client handles the :private_key_file, so you can remove from your application the bit that does that - this bit can be deleted:
```
if mauth_conf['private_key_file']
  mauth_conf['private_key'] = File.read(mauth_conf['private_key_file'])
end
```

- Autoloads are in place so that once you require 'mauth/client', you should not need to require mauth/rack, mauth/faraday, or mauth/request_and_response.

## 2.0.0
- Rewrite combining the mauth_signer and rack-mauth gems
