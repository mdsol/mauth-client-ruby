# Mauth-Client
[![Build Status](https://travis-ci.org/mdsol/mauth-client-ruby.svg?branch=master)](https://travis-ci.org/mdsol/mauth-client-ruby)

This gem consists of Mauth::Client, a class to manage the information needed to both sign and authenticate requests
and responses, and middlewares for Rack and Faraday which leverage the client's capabilities.

Mauth-Client exists in a variety of languages (.Net, Go, R etc.), see the [implementations list](doc/implementations.md) for more info.

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

Mauth is typically configured by a yaml file, [mauth.yml](doc/mauth.yml.md) - see its page for more documentation.
This is simply loaded and passed to either middleware or directly to a Mauth::Client instance.
See the documentation for [Mauth::Client#initialize](lib/mauth/client.rb) for more details of what it accepts. Usually you will want:

```ruby
mauth_config = Mauth::Client.default_config
```

The `.default_config` method takes a number of options to tweak its expectations regarding defaults. See the
documentation for [Mauth::Client.default_config](lib/mauth/client.rb) for details.

The `private_key` and `app_uuid` (which go in mauth.yml) enable local authentication (see section [Local Authentication](#local-authentication) below).
They’ll only work if the `app_uuid` has been stored in Mauth with a public key corresponding to the `private_key` in mauth.yml.

If you do not have an `app_uuid` and keypair registered with the mauth service, you can use mauth's remote request authentication by omitting those fields.
Mauth-Client will make a call to Mauth for every request in order to authenticate remotely.
Remote authentication therefore requires more time than local authentication.
You will not be able to sign your responses without an `app_uuid` and a private key, so `Mauth::Rack::ResponseSigner` cannot be used.

The `mauth_baseurl` and `mauth_api_version` are required in mauth.yml.
These tell the Mauth-Client where and how to communicate with the Mauth service.

The `v2_only_sign_requests` and `v2_only_authenticate` flags were added to facilitate conversion from the Mauth V1 protocol to the Mauth
V2 protocol. By default both of these flags are false. See [Protocol Versions](#protocol-versions) below for more information about the different versions.

|       | v2_only_sign_requests         | v2_only_authenticate                                                            |
|-------|------------------------------------|--------------------------------------------------------------------------------------|
| true  | requests are signed with only V2   | requests and responses are authenticated with only V2                                |
| false | requests are signed with V1 and V2 | requests and responses are authenticated with the highest available protocol version |

## Rack Middleware Usage

Mauth-Client provides a middleware for request authentication and response verification in mauth/rack.

```ruby
require 'mauth/rack'
```

If you are using other rack middlewares, the Mauth middleware MUST come FIRST in the stack of middlewares.
This means it is closest to the HTTP layer, furthest from the application.
If any other middlewares which modify the incoming request or outgoing response lie between the HTTP layer and the Mauth middleware, incoming requests will probably fail to authenticate and outgoing response signatures will be invalid (and fail when the requester tries to authenticate them).

Using these middlewares in rails consists of calls to `config.middleware.use` in the appropriate place (see [the Rails Guides](http://guides.rubyonrails.org/rails_on_rack.html) for more info).

Using the `Mauth::Rack::ResponseSigner` middleware is optional, but highly recommended.
If used, this should come before the `Mauth::Rack::RequestAuthenticator` middleware.
The ResponseSigner can be used ONLY if you have an `app_uuid` and `private_key` specified in your mauth configuration.

```ruby
config.middleware.use Mauth::Rack::ResponseSigner, mauth_config
```

Then request authentication:

```ruby
config.middleware.use Mauth::Rack::RequestAuthenticator, mauth_config
```

However, assuming you have a route `/app_status`, you probably want to skip request authentication for that.
There is a middleware (`RequestAuthenticatorNoAppStatus`) to make that easier:

```ruby
config.middleware.use Mauth::Rack::RequestAuthenticatorNoAppStatus, mauth_config
```

You may want to configure other conditions in which to bypass Mauth authentication.
The middleware takes an option on the `:should_authenticate_check` key, which is a ruby proc that is passed to the request's rack env and must result in a boolean.
If the result is true(ish), the middleware will authenticate the incoming request; if false, it will not.
The `:should_authenticate_check` parameter is OPTIONAL.
If omitted, all incoming requests will be authenticated.

Here are a few example `:should_authenticate_check` procs:

```ruby
mauth_config[:should_authenticate_check] = proc do |env|
  env['REQUEST_METHOD'] == 'GET'
end
config.middleware.use Mauth::Rack::RequestAuthenticator, mauth_config
```

Above, env is a hash of request parameters; this hash is generated by Rack.
The above proc will force the middleware to authenticate only GET requests.


Another example:

```ruby
mauth_config[:should_authenticate_check] = proc do |env|
  env['PATH_INFO'] == '/studies.json'
end
config.middleware.use Mauth::Rack::RequestAuthenticator, mauth_config
```

The above proc will force the rack middleware to authenticate only requests to the "/studies.json" path.
To authenticate a group of related URIs, considered matching `env['PATH_INFO']` with one or more regular expressions.

The configuration passed to the middlewares in the above examples (`mauth_config`) is used create a new instance of `Mauth::Client`.
If you are managing an Mauth::Client of your own for some reason, you can pass that in on the key `:mauth_client => your_client`, and omit any other Mauth::Client configuration.
`:should_authenticate_check` is handled by the middleware and should still be specified alongside `:mauth_client`, if you are using it.

When the request authentication middleware determines that a request is inauthentic, it will not call the application and will respond with a 401 status code along with an error, expressed in JSON
(Content-Type: application/json) with the following value:
```
{ "errors": { "mauth": ["Unauthorized"] } }
```
Successfully authenticated requests will be passed to the application, as will requests for which the `:should_authenticate_check` condition is false.

If the middleware is unable to authenticate the request because Mauth is unavailable and so cannot serve public keys, it responds with a 500 status code and an error expressed in JSON with the value:
```
{ "errors": { "mauth": ["Could not determine request authenticity"] } }
```

## Examples

Putting all this together, here are typical examples (in rails you would put that code in an initializer):

```ruby
mauth_config = Mauth::Client.default_config
require 'mauth/rack'
config.middleware.use Mauth::Rack::ResponseSigner, mauth_config
config.middleware.use Mauth::Rack:: RequestAuthenticatorNoAppStatus, mauth_config
```

With `:should_authenticate_check`:

```ruby
mauth_config = Mauth::Client.default_config
require 'mauth/rack'
config.middleware.use Mauth::Rack::ResponseSigner, mauth_config
# authenticate all requests which pass the some_condition_of check and aren't /app_status with Mauth
mauth_config[:should_authenticate_check] = proc do |env|
  some_condition_of(env)
end
config.middleware.use Mauth::Rack:: RequestAuthenticatorNoAppStatus, mauth_config
```

## Fake middleware

For testing purposes, you may wish to use middleware which does not perform actual authentication.
Mauth provides this, as `Mauth::Rack::RequestAuthenticationFaker`.
Requests are still checked for the presence of an Mauth signature - this is necessary as many applications rely on the `app_uuid` identified in the signature, so it cannot be ignored entirely.
However, the validity of the public key is not checked in the Mauth service, and the authenticity of the request is not verified by its signature.

This example code may augment the above examples to disable authentication in test mode:

```ruby
require 'mauth/fake/rack'
authenticator = Rails.env != 'test' ? Mauth::Rack::RequestAuthenticator : Mauth::Rack::RequestAuthenticationFaker
config.middleware.use authenticator, mauth_config
```

## Faraday Middleware Usage

If you are making outgoing HTTP requests using Faraday, adding Mauth Faraday middleware is much the same as adding rack middleware.
Building your connection will look like:

```ruby
Faraday.new(some_args) do |builder|
  builder.use Mauth::Faraday::RequestSigner, mauth_config
  builder.use Mauth::Faraday::ResponseAuthenticator, mauth_config
  builder.adapter Faraday.default_adapter
end
```

The Faraday middleware MUST come LAST in the stack of middleware.
As with the rack middleware, this means it will be right next to the HTTP adapter.

Only use the `Mauth::Faraday::ResponseAuthenticator` middleware if you are expecting the service you are communicating with to sign its responses (all services which are aware of Mauth _should_ be doing this).

`mauth_config` is the same as in Rack middleware, and as with the Rack middleware is used to initialize a `Mauth::Client` instance.
Also as with the Rack middleware, you can pass in a `Mauth::Client` instance you are using yourself on the `:mauth_client` key, and omit any other configuration.

Behavior is likewise similar to rack: if a `private_key` and `app_uuid` are specified, then ResponseAuthenticator will authenticate locally (see [Local Authentication](#local-authentication) below); if not, then it will go to the
mauth service to authenticate.
`Mauth::Faraday::RequestSigner` cannot be used without a `private_key` and `app_uuid`.

If a response which does not appear to be authentic is received by the `Mauth::Faraday::ResponseAuthenticator` middleware, a `Mauth::InauthenticError` will be raised.

If the Mauth service cannot be reached, and therefore the authenticity of a response cannot be verified by ResponseAuthenticator, then a `Mauth::UnableToAuthenticateError` will be raised.

## Other Request and Response signing

If you are not using Faraday, you will need to sign your own requests.

Instantiate a `Mauth::Client` with the same configuration as the middlewares, as documented on [Mauth::Client#initialize](lib/mauth/client.rb).
We'll call this `mauth_client`.

`mauth_client` has a method `#signed_headers` which takes either a `Mauth::Request` or `Mauth::Response` object, and generates HTTP headers which can be added to the request or response to indicate authenticity.
Create a `Mauth::Request` object from the information in your HTTP request, whatever its form:

```ruby
require 'mauth/request_and_response'
request = Mauth::Request.new(verb: my_verb, request_url: my_request_url, body: my_body, query_string: my_query_string)
```
`mauth_client.signed_headers(request)` will then return mauth headers which you can apply to your request.

## Local Authentication

When doing local authentication, the Mauth-Client will periodically fetch and cache public keys from Mauth.
Each public key will be cached locally for 60 seconds.
Applications which connect frequently to the app will benefit most from this caching strategy.
When fetching public keys from Mauth, the following rules apply:

1. If Mauth returns the public key for a given `app_uuid`, Mauth-Client will refresh its local cache with this new public key.
2. If Mauth cannot find the public key for a given `app_uuid` (i.e. returns a 404 status code), Mauth-Client will remove the corresponding public key from its local cache and authentication of any message from the application with this public key will fail as a consequence.
3. If the request to Mauth times out or Mauth returns a 500 status code, the requested public key will not be removed from local Mauth-Client cache (if it exists there in the first place).
   The cached version will continue to be used for local authentication until Mauth::Client is able to again communicate with Mauth.

## Warning

During development classes are typically not cached in Rails applications.
If this is the case, be aware that the Mauth-Client middleware object will be instantiated anew for each request;
this will cause applications performing local authentication to fetch public keys before each request is authenticated.

## Protocol Versions

The mauth V2 protocol was added as of v5.0.0. This protocol updates the string_to_sign to include query parameters, uses different authentication header names, and has a few other changes. See this document for more information: (DOC?). By default Mauth-Client will authenticate incoming requests with only the highest version of the protocol present, and sign their outgoing responses with only the version used to authenticate the request. By default Mauth-Client will sign outgoing requests with both the V1 and V2 protocols, and authenticate their incoming responses with only the highest version of the protocol present.
If the `v2_only_sign_requests` flag is true all outgoing requests will be signed with only the V2 protocol (outgoing responses will still be signed with whatever protocol used to authenticate the request). If the `v2_only_authenticate` flag is true then Mauth-Client will reject any incoming request or incoming response that does not use the V2 protocol.
