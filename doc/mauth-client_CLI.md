# MAuth-Client CLI Tool

MAuth-Client provides a Command Line Interface (CLI) tool to make MAuth-signed requests and verify MAuth-signed responses.

## Installation

The MAuth-Client CLI is part of the MAuth Client gem, refer to [the README](../README.md#installation) for installation instructions.

## Configuration

The CLI is configured with the [MAuth environment variables](../README.md#Configuration) - see the readme doc for instructions.

## Usage

The mauth-client executable should be available with `bundle exec`, once it has been installed in your Gemfile.
If you installed the gem manually, you may not need to run `bundle exec`.

```
$ bundle exec mauth-client --help
Usage: mauth-client [options] <verb> <url> [body]
    -v, --[no-]verbose               Run verbosely - output is like curl -v (this is the default)
    -q                               Run quietly - only outputs the response body (same as --no-verbose)
        --[no-]authenticate          Authenticate the response received
        --[no-]color                 Color the output (defaults to color if the output device is a TTY)
    -t, --content-type CONTENT-TYPE  Sets the Content-Type header of the request
    -H, --header LINE                accepts a json string of additional headers to included. IE 'cache-expirey: 10, other: value
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

MAuth-Client CLI's default output is designed to look like the output of `curl -v`.
It includes all headers, body, and other components of the http request.
This can be suppressed with the `-q` (quiet) option, in which case only the response body will be output.
The normal output (not the quiet version) is colorized by default if connected to a tty device (e.g. a terminal).
