# mauth.yml

The conventional way to configure MAuth-Client for your project is a is a YAML file which lives in your project at 
`config/mauth.yml`. It is keyed on environment, and for the most part its contents are passed directly to instantiate 
an MAuth::Client. See the documentation for [MAuth::Client#initialize][] (link requires 
Medidata network or VPN) for more details of what it accepts. 

[MAuth::Client#initialize]: https://columbo-portal-current.s3.amazonaws.com/mauth/mauth-client-design/MAuth/Client.html#initialize-instance_method

Note: __PRIVATE KEYS MUST NOT BE COMMITTED INTO YOUR GIT REPOSITORY NOR PUSHED TO GITHUB.__

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
```

### Keys:

- `private_key` - See Generating Keypairs for MAuth for instructions on generation. Required for signing and for 
  authenticating responses. may be omitted if only remote authentication of requests is being performed. __PRIVATE 
  KEYS MUST NOT BE COMMITTED INTO YOUR GIT REPOSITORY NOR PUSHED TO GITHUB.__
- `private_key_file`  - May be used instead of private_key; mauth-client will load the file instead. 
- `app_uuid` - Required in the same circumstances where a private_key is required. If you are working in your local 
  computer and need a personal app_uuid please send a request to devops@mdsol.com, including your public key 
  ([Generating Keypairs for MAuth][]).
- `mauth_baseurl` - required if authenticating (but not for signing). needed for local authentication to retrieve 
  public keys; needed for remote authentication. There are 2 authoritative values for `mauth_baseurl`:
  - `https://mauth-innovate.imedidata.com` to be used for all non-production services and clients, including local 
    development.
  - `https://mauth.imedidata.com` to be used only for all production services and clients.
- `mauth_api_version` - Required for authentication, but not for signing. only `v1` exists / is supported as of 
  this writing.

[Generating Keypairs for MAuth]: https://sites.google.com/a/mdsol.com/knowledgebase/home/departments/engineering/on-demand-portfolio/services/core-services/mauth/mauth-client/generating-keypairs-for-mauth

## Usage in your application

You will load mauth.yml, merge in any other configuration that is needed for your usage, and pass the config along to 
instantiate a `MAuth::Client` or a middleware. 

See the [MAuth Client](MAuth_Client.md) page for more detail. 

## Usage in MAuth-Client CLI tool

See __Configuration__ in the [MAuth-Client CLI Tool](mauth-client_CLI.md#configuration) page.
