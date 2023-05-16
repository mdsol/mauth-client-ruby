# Examples

## Configuration

After obtaining valid credentials you need to set the `MAUTH_APP_UUID`, `MAUTH_PRIVATE_KEY_FILE` and `REFERENCES_HOST` environment variables.
You also need to provide a mauth key and put it in the `mauth_key` file.

This folder contains its own Gemfile file to manage dependencies so you need to run
```
bundle install
```
before trying any of the scripts.


## Fetching a given user's info

Simply run the provided shell script by passing an search term, for instance:
```
MAUTH_APP_UUID=<APP UUID> MAUTH_PRIVATE_KEY_FILE=./mauth_key REFERENCES_HOST=https://references-innovate.imedidata.net ./get_country_info.rb Albania
```

This should print the country's info, something along the lines of:
```
[
  {
    "uuid": "9301ff5a-6703-11e1-b86c-0800200c9a66",
    "name": "Albania",
    "three_letter_code": "ALB",
    "two_letter_code": "AL",
    "version": "2021-06-30T12:00:00Z",
    "country_code": "ALB"
  }
]
```
