# Upgrade Guide

## Versions
- [Upgrading to 7.0.0](#upgrading-to-700)

### Upgrading to 7.0.0

Version 7.0.0 drops dice_bag.

Please remove the following files and update the `.gitignore` file accordingly:
- `config/initializers/mauth.rb.dice`
- `config/mauth_key`
- `config/mauth_key.dice`
- `config/mauth.yml`
- `config/mauth.yml.dice`
