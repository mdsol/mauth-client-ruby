# Examples

## Configuration

After obtaining valid credentials you need to edit the `config.yml` file and set the `app_uuid` accordingly.
You also need to provide a mauth key and put it in the `mauth_key` file.
See [the mauth config file doc](../doc/mauth.yml.md) for more information.

This folder contains its own Gemfile and Gemfile.lock files to manage dependencies so you need to run
```
bundle install
```
before trying any of the scripts.


## Fetching a given user's info

Simply run the provided shell script by passing an user's UUID, for instance:
```
./get_user_info.rb 4735d013-8d78-4980-8846-fbecf0db0b8e
```

This should print the user's info, something along the lines of:
```
{
  "user": {
    "login": "name",
    "email": "the.email.address@example.com",
    "uuid": "4735d013-8d78-4980-8846-fbecf0db0b8e",
    ...
  }
}
```
