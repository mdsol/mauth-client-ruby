# Upgrade Guide

## Versions
- [Upgrading to 7.0.0](#upgrading-to-700)

### Upgrading to 7.0.0

Version 7.0.0 drops dice_bag.

Please remove the following files and update the `.gitignore` file accordingly:
- `config/initializers/mauth.rb.dice` (rename to `mauth.rb` and remove the top line `<%= warning.as_yaml_comment %>`)
- `config/mauth_key`
- `config/mauth_key.dice`
- `config/mauth.yml`
- `config/mauth.yml.dice`

Prepend `MAUTH_` to the following environment variables:
- `V2_ONLY_SIGN_REQUESTS`
- `V2_ONLY_AUTHENTICATE`
- `DISABLE_FALLBACK_TO_V1_ON_V2_FAILURE`
- `V1_ONLY_SIGN_REQUESTS`
