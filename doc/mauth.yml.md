# mauth.yml

The conventional way to configure MAuth-Client for your project is through a YAML file which lives in your project at `config/mauth.yml`.
It is keyed on environment, and for the most part its contents are passed directly to instantiate an MAuth::Client.
See the documentation for [MAuth::Client#initialize](../lib/mauth/client.rb) for more details of what it accepts.

## Generating keys

To generate a private key (`mauth_key`) and its public counterpart (`mauth_key.pub`) run:

```
openssl genrsa -out mauth_key 2048
openssl rsa -in mauth_key -pubout -out mauth_key.pub
```

## Format

```yaml
common: &common
  mauth_baseurl: https://mauth-innovate.imedidata.com
  mauth_api_version: v1
  app_uuid: 123we997-0333-44d8-8fCf-5dd555c5bd51
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    AIIEowIBAAKCAQEAwLYWYcKrCAl7uWVlkwzBcBXRiRREqGYLXEnRGgDrlqbY+lDg
    gwMNga3ylckui/rTUZhtefx1MLtxgnTGiil45eleoJgjdfsOO5yXzUA46KW0cuL4
    ...
    oEKe4QKBgFNbVJp3Zut83MzpN4Zu7/wZ/+q9ds9WMMxWb4hUugKQTPjsgj+8tCqa
    SIY2exfsy7Y8NoOnBPlGiXKhgaF21T8kqV9C7R6OAuP0U6CgMJnINx/UjozvBENH
    Ux45QdvRd6vai8nHp7AgV7rr55SxXAZVgATll84uBUpfpmC6YK/j
    -----END RSA PRIVATE KEY-----

production:
  <<: *common
development:
  <<: *common
test:
  <<: *common
```

Optionally you can load the private key from a file:

```yaml
common: &common
  mauth_baseurl: https://mauth-innovate.imedidata.com
  mauth_api_version: v1
  app_uuid: 123we997-0333-44d8-8fCf-5dd555c5bd51
  private_key_file: config/my_mauth_private.key

production:
  <<: *common
development:
  <<: *common
test:
  <<: *common
```

## Configuration options

- `private_key` - Required for signing and for authenticating responses. May be omitted if only remote authentication of requests is being performed.
- `private_key_file` - May be used instead of `private_key`, mauth-client will load the file instead.
- `app_uuid` - Required in the same circumstances where a `private_key` is required.
- `mauth_baseurl` - Required for authentication but not for signing. Needed for local authentication to retrieve public keys and for remote authentication. Usually this is `https://mauth.imedidata.com` for production.
- `mauth_api_version` - Required for authentication but not for signing. only `v1` exists as of this writing.

## Usage in your application

Load mauth.yml, merge in any other configuration that is needed for your usage, and pass the config along to instantiate a `MAuth::Client` or a middleware.
See the [README](../README.md) for more detail.

## Usage in MAuth-Client executables (mauth-client, mauth-proxy)

See the [MAuth-Client CLI Tool doc](./mauth-client_CLI.md#configuration).
