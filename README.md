# MAuth-Client
[![Build Status](https://travis-ci.org/mdsol/mauth-client-ruby.svg?branch=master)](https://travis-ci.org/mdsol/mauth-client-ruby)

This gem consists of MAuth::Client, a class to manage the information needed to both sign and authenticate requests
and responses, and middlewares for Rack and Faraday which leverage the client's capabilities.

MAuth-Client exists in a variety of languages (.Net, Go, R etc.), see the [implementations list](doc/implementations.md) for more info.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'mauth-client'
```

And then execute:
```
$ bundle
```

Or install it yourself as:
```
$ gem install mauth-client
```


## Configuration

Configuration is set through environment variables:

- `MAUTH_PRIVATE_KEY`
  - Required for signing and for authenticating responses. May be omitted if only remote authentication of requests is being performed.

- `MAUTH_PRIVATE_KEY_FILE`
  - May be used instead of `MAUTH_PRIVATE_KEY`, mauth-client will load the file instead.

- `MAUTH_APP_UUID`
  - Required in the same circumstances where a `private_key` is required.

- `MAUTH_URL`
  - Required for authentication but not for signing. Needed for local authentication to retrieve public keys and for remote authentication. Usually this is `https://mauth.imedidata.com` for production.

- `MAUTH_API_VERSION`
  - Required for authentication but not for signing. only `v1` exists as of this writing. Defaults to `v1`.

- `V2_ONLY_SIGN_REQUESTS`
  - If true, all outgoing requests will be signed with only the V2 protocol. Defaults to false.

- `V2_ONLY_AUTHENTICATE`
  - If true, any incoming request or incoming response that does not use the V2 protocol will be rejected. Defaults to false.

- `DISABLE_FALLBACK_TO_V1_ON_V2_FAILURE`
  - If true, any incoming V2 requests that fail authentication will not fall back to V1 authentication. Defaults to false.

- `V1_ONLY_SIGN_REQUESTS`
  - If true, all outgoing requests will be signed with only the V1 protocol. Defaults to true. Note, cannot be `true` if `V2_ONLY_SIGN_REQUESTS` is also `true`.


This is simply loaded and passed to either middleware or directly to a MAuth::Client instance.
See the documentation for [MAuth::Client#initialize](lib/mauth/client.rb) for more details of what it accepts. Usually you will want:

```ruby
MAUTH_CONF = MAuth::Client.default_config
```

The `.default_config` method takes a number of options to tweak its expectations regarding defaults. See the
documentation for [MAuth::Client.default_config](lib/mauth/client.rb) for details.

The `private_key` and `app_uuid` enable local authentication (see section [Local Authentication](#local-authentication) below).
They’ll only work if the `app_uuid` has been stored in MAuth with a public key corresponding to the `private_key`.

If you do not have an `app_uuid` and keypair registered with the mauth service, you can use mauth's remote request authentication by omitting those fields.
MAuth-Client will make a call to MAuth for every request in order to authenticate remotely.
Remote authentication therefore requires more time than local authentication.
You will not be able to sign your responses without an `app_uuid` and a private key, so `MAuth::Rack::ResponseSigner` cannot be used.

The `mauth_baseurl` and `mauth_api_version` are required.
These tell the MAuth-Client where and how to communicate with the MAuth service.

The `v2_only_sign_requests` and `v2_only_authenticate` flags were added to facilitate conversion from the MAuth V1 protocol to the MAuth
V2 protocol. By default both of these flags are false. See [Protocol Versions](#protocol-versions) below for more information about the different versions.

|       | v2_only_sign_requests         | v2_only_authenticate                                                            |
|-------|------------------------------------|--------------------------------------------------------------------------------------|
| true  | requests are signed with only V2   | requests and responses are authenticated with only V2                                |
| false | requests are signed with V1 and V2 | requests and responses are authenticated with the highest available protocol version |

### Generating keys

To generate a private key (`mauth_key`) and its public counterpart (`mauth_key.pub`) run:

```
openssl genrsa -out mauth_key 2048
openssl rsa -in mauth_key -pubout -out mauth_key.pub
```

## Rack Middleware Usage

MAuth-Client provides a middleware for request authentication and response verification in mauth/rack.

```ruby
require 'mauth/rack'
```

If you are using other rack middlewares, the MAuth middleware MUST come FIRST in the stack of middlewares.
This means it is closest to the HTTP layer, furthest from the application.
If any other middlewares which modify the incoming request or outgoing response lie between the HTTP layer and the MAuth middleware, incoming requests will probably fail to authenticate and outgoing response signatures will be invalid (and fail when the requester tries to authenticate them).

Using these middlewares in rails consists of calls to `config.middleware.use` in the appropriate place (see [the Rails Guides](http://guides.rubyonrails.org/rails_on_rack.html) for more info).

Using the `MAuth::Rack::ResponseSigner` middleware is optional, but highly recommended.
If used, this should come before the `MAuth::Rack::RequestAuthenticator` middleware.
The ResponseSigner can be used ONLY if you have an `app_uuid` and `private_key` specified in your mauth configuration.

```ruby
config.middleware.use MAuth::Rack::ResponseSigner, MAUTH_CONF
```

Then request authentication:

```ruby
config.middleware.use MAuth::Rack::RequestAuthenticator, MAUTH_CONF
```

However, assuming you have a route `/app_status`, you probably want to skip request authentication for that.
There is a middleware (`RequestAuthenticatorNoAppStatus`) to make that easier:

```ruby
config.middleware.use MAuth::Rack::RequestAuthenticatorNoAppStatus, MAUTH_CONF
```

You may want to configure other conditions in which to bypass MAuth authentication.
The middleware takes an option on the `:should_authenticate_check` key, which is a ruby proc that is passed to the request's rack env and must result in a boolean.
If the result is true(ish), the middleware will authenticate the incoming request; if false, it will not.
The `:should_authenticate_check` parameter is OPTIONAL.
If omitted, all incoming requests will be authenticated.

Here are a few example `:should_authenticate_check` procs:

```ruby
MAUTH_CONF[:should_authenticate_check] = proc do |env|
  env['REQUEST_METHOD'] == 'GET'
end
config.middleware.use MAuth::Rack::RequestAuthenticator, MAUTH_CONF
```

Above, env is a hash of request parameters; this hash is generated by Rack.
The above proc will force the middleware to authenticate only GET requests.


Another example:

```ruby
MAUTH_CONF[:should_authenticate_check] = proc do |env|
  env['PATH_INFO'] == '/studies.json'
end
config.middleware.use MAuth::Rack::RequestAuthenticator, MAUTH_CONF
```

The above proc will force the rack middleware to authenticate only requests to the "/studies.json" path.
To authenticate a group of related URIs, considered matching `env['PATH_INFO']` with one or more regular expressions.

The configuration passed to the middlewares in the above examples (`MAUTH_CONF`) is used create a new instance of `MAuth::Client`.
If you are managing an MAuth::Client of your own for some reason, you can pass that in on the key `:mauth_client => your_client`, and omit any other MAuth::Client configuration.
`:should_authenticate_check` is handled by the middleware and should still be specified alongside `:mauth_client`, if you are using it.

When the request authentication middleware determines that a request is inauthentic, it will not call the application and will respond with a 401 status code along with an error, expressed in JSON
(Content-Type: application/json) with the following value:
```
{ "errors": { "mauth": ["Unauthorized"] } }
```
Successfully authenticated requests will be passed to the application, as will requests for which the `:should_authenticate_check` condition is false.

If the middleware is unable to authenticate the request because MAuth is unavailable and so cannot serve public keys, it responds with a 500 status code and an error expressed in JSON with the value:
```
{ "errors": { "mauth": ["Could not determine request authenticity"] } }
```

## Examples

Putting all this together, here are typical examples (in rails you would put that code in an initializer):

```ruby
require 'mauth/rack'

MAUTH_CONF = MAuth::Client.default_config

# ResponseSigner OPTIONAL; only use if you are registered in mauth service
Rails.application.config.middleware.insert_after Rack::Runtime, MAuth::Rack::ResponseSigner, MAUTH_CONF
if Rails.env.test? || Rails.env.development?
  require 'mauth/fake/rack'
  Rails.application.config.middleware.insert_after MAuth::Rack::ResponseSigner, MAuth::Rack::RequestAuthenticationFaker, MAUTH_CONF
else
  Rails.application.config.middleware.insert_after MAuth::Rack::ResponseSigner, MAuth::Rack::RequestAuthenticatorNoAppStatus, MAUTH_CONF
end
```

With `:should_authenticate_check`:

```ruby
require 'mauth/rack'

MAUTH_CONF = MAuth::Client.default_config
# authenticate all requests which pass the some_condition_of check and aren't /app_status with MAuth
MAUTH_CONF[:should_authenticate_check] = proc do |env|
  some_condition_of(env)
end

# ResponseSigner OPTIONAL; only use if you are registered in mauth service
Rails.application.config.middleware.insert_after Rack::Runtime, MAuth::Rack::ResponseSigner, MAUTH_CONF
if Rails.env.test? || Rails.env.development?
  require 'mauth/fake/rack'
  Rails.application.config.middleware.insert_after MAuth::Rack::ResponseSigner, MAuth::Rack::RequestAuthenticationFaker, MAUTH_CONF
else
  Rails.application.config.middleware.insert_after MAuth::Rack::ResponseSigner, MAuth::Rack::RequestAuthenticatorNoAppStatus, MAUTH_CONF
end
```

## Fake middleware

For testing purposes, you may wish to use middleware which does not perform actual authentication.
MAuth provides this, as `MAuth::Rack::RequestAuthenticationFaker`.
Requests are still checked for the presence of an MAuth signature - this is necessary as many applications rely on the `app_uuid` identified in the signature, so it cannot be ignored entirely.
However, the validity of the public key is not checked in the MAuth service, and the authenticity of the request is not verified by its signature.

This example code may augment the above examples to disable authentication in test mode:

```ruby
require 'mauth/fake/rack'
authenticator = Rails.env != 'test' ? MAuth::Rack::RequestAuthenticator : MAuth::Rack::RequestAuthenticationFaker
config.middleware.use authenticator, MAUTH_CONF
```

## Faraday Middleware Usage

If you are making outgoing HTTP requests using Faraday, adding MAuth Faraday middleware is much the same as adding rack middleware.
Building your connection will look like:

```ruby
Faraday.new(some_args) do |builder|
  builder.use MAuth::Faraday::RequestSigner, MAUTH_CONF
  builder.use MAuth::Faraday::ResponseAuthenticator, MAUTH_CONF
  builder.adapter Faraday.default_adapter
end
```

The Faraday middleware MUST come LAST in the stack of middleware.
As with the rack middleware, this means it will be right next to the HTTP adapter.

Only use the `MAuth::Faraday::ResponseAuthenticator` middleware if you are expecting the service you are communicating with to sign its responses (all services which are aware of MAuth _should_ be doing this).

`MAUTH_CONF` is the same as in Rack middleware, and as with the Rack middleware is used to initialize a `MAuth::Client` instance.
Also as with the Rack middleware, you can pass in a `MAuth::Client` instance you are using yourself on the `:mauth_client` key, and omit any other configuration.

Behavior is likewise similar to rack: if a `private_key` and `app_uuid` are specified, then ResponseAuthenticator will authenticate locally (see [Local Authentication](#local-authentication) below); if not, then it will go to the
mauth service to authenticate.
`MAuth::Faraday::RequestSigner` cannot be used without a `private_key` and `app_uuid`.

If a response which does not appear to be authentic is received by the `MAuth::Faraday::ResponseAuthenticator` middleware, a `MAuth::InauthenticError` will be raised.

If the MAuth service cannot be reached, and therefore the authenticity of a response cannot be verified by ResponseAuthenticator, then a `MAuth::UnableToAuthenticateError` will be raised.

## Other Request and Response signing

If you are not using Faraday, you will need to sign your own requests.

Instantiate a `MAuth::Client` with the same configuration as the middlewares, as documented on [MAuth::Client#initialize](lib/mauth/client.rb).
We'll call this `mauth_client`.

`mauth_client` has a method `#signed_headers` which takes either a `MAuth::Request` or `MAuth::Response` object, and generates HTTP headers which can be added to the request or response to indicate authenticity.
Create a `MAuth::Request` object from the information in your HTTP request, whatever its form:

```ruby
require 'mauth/request_and_response'
request = MAuth::Request.new(verb: my_verb, request_url: my_request_url, body: my_body, query_string: my_query_string)
```
`mauth_client.signed_headers(request)` will then return mauth headers which you can apply to your request.

## Local Authentication

When doing local authentication, the MAuth-Client will periodically fetch and cache public keys from MAuth.
Each public key will be cached locally for 60 seconds.
Applications which connect frequently to the app will benefit most from this caching strategy.
When fetching public keys from MAuth, the following rules apply:

1. If MAuth returns the public key for a given `app_uuid`, MAuth-Client will refresh its local cache with this new public key.
2. If MAuth cannot find the public key for a given `app_uuid` (i.e. returns a 404 status code), MAuth-Client will remove the corresponding public key from its local cache and authentication of any message from the application with this public key will fail as a consequence.
3. If the request to MAuth times out or MAuth returns a 500 status code, the requested public key will not be removed from local MAuth-Client cache (if it exists there in the first place).
   The cached version will continue to be used for local authentication until MAuth::Client is able to again communicate with MAuth.

## Warning

During development classes are typically not cached in Rails applications.
If this is the case, be aware that the MAuth-Client middleware object will be instantiated anew for each request;
this will cause applications performing local authentication to fetch public keys before each request is authenticated.

## Protocol Versions

The mauth V2 protocol was added as of v5.0.0. This protocol updates the string_to_sign to include query parameters, uses different authentication header names, and has a few other changes. See this document for more information: (DOC?). By default MAuth-Client will authenticate incoming requests with only the highest version of the protocol present, and sign their outgoing responses with only the version used to authenticate the request. By default MAuth-Client will sign outgoing requests with both the V1 and V2 protocols, and authenticate their incoming responses with only the highest version of the protocol present.
If the `v2_only_sign_requests` flag is true all outgoing requests will be signed with only the V2 protocol (outgoing responses will still be signed with whatever protocol used to authenticate the request). If the `v2_only_authenticate` flag is true then MAuth-Client will reject any incoming request or incoming response that does not use the V2 protocol.
