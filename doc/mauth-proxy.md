# mauth-proxy executable

## Overview

mauth-proxy is a command-line tool to forward requests to a service, signing each one with a Mauth signature and verifying responses from the service.

mauth-proxy wraps a Rack server, which listens on localhost (external connections are not allowed, for security).
mauth-proxy takes each request, signs it with a specified Mauth configuration, and makes a request to the given service.
The response from the service is authenticated with Mauth, and is returned as the response to the original request.

The intent is to allow users to point any HTTP or REST client they care to use at a service which authenticates with Mauth, without the client needing to know how to generate Mauth signatures or authenticate Mauth-signed responses.

The proxy has two modes: single-target and browser proxy mode. In browser proxy mode, it can be configured as a HTTP proxy in a browser and will direct the requests to any URL in the request while signing requests to URLs that are listed in the command line.
In single-target mode, all requests will be directed to the server specified in the command line.

## Usage

Single target mode:
```
$ bundle exec mauth-proxy -p 3452 https://eureka.imedidata.com/
```

This will launch a rack server, listening on port 3452.
When a request is made to this server on a particular path - say `http://localhost:3452/v1/apis`, then mauth-proxy will make a mauth-signed request to `https://eureka.imedidata.com/v1/apis`, then authenticate the response and return that response to the original request.

Browser proxy mode:
```
$ bundle exec mauth-proxy -p 3452 --browser_proxy http://localhost:3000 http://localhost:9292
```

For this mode, add localhost:3452 in your browser's proxy configuration and access the service you want to use.
If the beginning of the requested URL matches one of the URLs you specified, it will be signed and authenticated.


## Options

The location of the mauth configuration can be specified or infered automatically, see the [Mauth-Client CLI Tool doc](./mauth-client_CLI.md#configuration) for more details.

The last command-line argument MUST be a target URI to which requests will be forwarded.

The `--no-authenticate` option disables response authentication from the target service.

The `--browser_proxy` option switches to browser proxy mode and is intended to be used when the proxy is used in conjunction with a web browser that is set to use this proxy.

The `--header` Accepts a [key]:[value] header definition to include, e.g. -h "Accept:application/json". It can be used multiple times for multiple headers.

All other options are passed along to rack.
Available options can be viewed by running rackup -h, and are also listed below:

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
