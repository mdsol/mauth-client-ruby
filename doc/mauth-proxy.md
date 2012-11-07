# mauth-proxy executable

## Overview

mauth-proxy is a command-line tool to forward requests to a service, signing each one with a MAuth signature and 
verifying responses from the service. 

mauth-proxy wraps a Rack server, which listens on localhost (external connections are not allowed, for security). 
mauth-proxy takes each request, signs it with a specified MAuth configuration, and makes a request to the given 
service. The response from the service is authenticated with MAuth, and is returned as the response to the original 
request. 

The intent is to allow users to point any HTTP or REST client they care to use at a service which authenticates with 
MAuth, without the client needing to know how to generate MAuth signatures or authenticate MAuth-signed responses. 

## Usage

```
$ bundle exec mauth-proxy -p 3452 https://eureka.imedidata.com/
```

This will launch a rack server, listening on port 3452. When a request is made to this server on a particular path - 
say `http://localhost:3452/v1/apis`, then mauth-proxy will make a mauth-signed request to 
`https://eureka.imedidata.com/v1/apis`, then authenticate the response and return that response to the original 
request.

## Options
The location of the mauth configuration is guessed as config/mauth.yml, or may be specified with the 
`MAUTH_CONFIG_YML` environment variable. e.g.:

```
$ MAUTH_CONFIG_YML=~/myproject/config/mauth.yml bundle exec mauth-proxy -p 3452 https://eureka.imedidata.com/
```

The last command-line argument MUST be a target URI to which requests will be forwarded. 

The `--no-authenticate` option disables response authentication from the target service.

All other options are passed along to rack. Available options can be viewed by running rackup -h, and are also listed 
below:

```
Ruby options:
  -e, --eval LINE          evaluate a LINE of code
  -d, --debug              set debugging flags (set $DEBUG to true)
  -w, --warn               turn warnings on for your script
  -I, --include PATH       specify $LOAD_PATH (may be used more than once)
  -r, --require LIBRARY    require the library, before executing your script

Rack options:
  -s, --server SERVER      serve using SERVER (webrick/mongrel)
  -o, --host HOST          listen on HOST (default: 0.0.0.0)
  -p, --port PORT          use PORT (default: 9292)
  -O NAME[=VALUE],         pass VALUE to the server as option NAME. If no VALUE, sets it to true. Run 'rackup -s SERVER -h' to get a list of options for SERVER
      --option
  -E, --env ENVIRONMENT    use ENVIRONMENT for defaults (default: development)
  -D, --daemonize          run daemonized in the background
  -P, --pid FILE           file to store PID (default: rack.pid)

Common options:
  -h, -?, --help           Show this message
      --version            Show version
```
