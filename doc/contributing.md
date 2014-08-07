# Contributing

## General Information

* Check out the latest master to make sure the feature hasn't been implemented or the bug hasn't been fixed yet
* Check out the issue tracker to make sure someone already hasn't requested it and/or contributed it
* Fork the project
* Start a feature/bugfix branch
* Commit and push until you are happy with your contribution
* Make sure to add tests for it. This is important so I don't break it in a future version unintentionally.
* Please try not to mess with the Rakefile, version, or history. If you want to have your own version, or is otherwise necessary, that is fine, but please isolate to its own commit so I can cherry-pick around it.

## Running Tests

To run tests, first do a `bundle install` to make sure your gems are up to date.  Next, tell the tests where your mauth config 
file is.  Most likely, you should do this by executing:

```
export MAUTH_CONFIG_YML=full/path/to/spec/config_root/config/mauth.yml
```

Finally, execute `bundle exec rspec spec`.  

You may see intermittent errors with integration specs due to network hiccups; if such a thing happens, just run the spec again and
it should pass.
