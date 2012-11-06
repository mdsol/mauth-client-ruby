# MAuth-Client CLI Tool

MAuth-Client provides a Command Line Interface (CLI) tool to make MAuth-signed requests and verify MAuth-signed 
responses. 

## Installation

The mauth-client CLI is part of the MAuth Client gem, which can be installed per the section __Installation__ in the 
[MAuth Client](MAuth_Client.md#installation) page. Short version: add it to your Gemfile and `bundle install`, or 
download the gem and `gem install` it. 

## Configuration

The CLI is configured with a [mauth.yml](mauth.yml.md) file - see its page for instructions. 

The mauth-client CLI tool looks for mauth.yml configuration in several places:

- if an environment variable `MAUTH_CONFIG_YML` points to an existing file, mauth-client will use that file if it 
  exists. 
- if you have a file `~/.mauth_config.yml` then it will use that. this is useful if you have your own mauth key. 
- if you are in a directory relative to which a config/mauth.yml exists, it will use that. this is useful if you are 
  working in a project which uses mauth and has a key configured. 
- if you are in a directory in which a file mauth.yml exists, it will use that. 

mauth.yml is expected to contain, at the top level, an environment key or keys. mauth-client checks environment 
variables `RAILS_ENV` and `RACK_ENV` to determine the environment, and defaults to 'development' if none of these are 
set. 

## Usage

The mauth-client executable should be available with `bundle exec`, once it has been installed in your Gemfile. Or if 
you downloaded the gem and installed it with gem install, you may not need the `bundle exec`. 

```
$ bundle exec mauth-client --help
Usage: mauth-client [options] <verb> <url> [body]
    -v, --[no-]verbose               Run verbosely - output is like curl -v (this is the default)
    -q                               Run quietly - only outputs the response body (same as --no-verbose)
        --[no-]authenticate          Authenticate the response received
        --[no-]color                 Color the output (defaults to color if the output device is a TTY)
    -t, --content-type CONTENT-TYPE  Sets the Content-Type header of the request
        --no-ssl-verify              Disables SSL verification - use cautiously!
```

Examples:

```
bundle exec mauth-client GET https://eureka-innovate.imedidata.com/v1/apis
```

```
bundle exec mauth-client GET https://eureka-innovate.imedidata.com/v1/deployments
```

```
bundle exec mauth-client POST https://eureka-innovate.imedidata.com/v1/deployments '{"baseURI": "https://cupcakes.imedidata.com", "stage": "production", "apis": [{"name": "cupcakes", "version": "v1.0.0"}]}'
```

## Output

mauth-client CLI's default output is designed to look like the output of `curl -v`. It includes all headers, body, 
and other components of the http request. This can be suppressed with the `-q` (quiet) option, in which case only the 
response body will be output. The normal output (not the quiet version) is colorized by default if connected to a tty 
device (e.g. a terminal). An example of normal (not quiet) output follows (color not shown):

```
* connect to eureka-innovate.imedidata.com on port 
* getting our SSL on
> GET /deployments HTTP/1.1
> X-MWS-Authentication: MWS 2a02c997-0193-44d8-8fcf-5dd078c5bd51:S+78rwZ6S ... Q1TqdFPuJtc89jZz91+5EcBy3Q==
> X-MWS-Time: 1331735868
> 
< HTTP/1.1 200
< content-type: application/json
< connection: close
< status: 200
< x-powered-by: Phusion Passenger (mod_rails/mod_rack) 3.0.9
< vary: Accept
< content-length: 270
< x-mws-authentication: MWS 81e3062f-10d5-4e6e-b9f7-ffef3444d3a5:wbHwXa5u ... XoXIvnQpHtNYw==
< x-mws-time: 1331735869
< server: nginx/1.0.6 + Phusion Passenger 3.0.9 (mod_rails/mod_rack)
< 
< {
<   "items": [
<     {
<       "uuid": "661a2433-88f6-4992-858d-bc96b803d17b",
<       "baseURI": "https://cupcakes.imedidata.com",
<       "stage": "production",
<       "apis": [
<         {
<           "_link": true,
<           "href": "/v1/apis/cupcakes/v1.0.0",
<           "resource": "apis",
<           "attributes": {
<             "name": "cupcakes",
<             "version": "v1.0.0"
<           },
<           "rel": "related"
<         }
<       ]
<     }
<   ]
< }
< 
```
