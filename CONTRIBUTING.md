# Contributing

## General Information

* Check out the latest develop to make sure the feature hasn't been implemented or the bug hasn't been fixed yet
* Check out the issue tracker to make sure someone already hasn't requested it and/or contributed it
* Fork the project
* Start a feature/bugfix branch
* Commit and push until you are happy with your contribution
* Make sure to add tests for it. This is important so I don't break it in a future version unintentionally.

## Running Tests

To run tests, first run `bundle install`.

Next, run the tests:

```
bundle exec rspec
```

## Running Benchmark

If you make changes which could affect performance, please run the benchmark before and after the change as sanity check.

```
bundle exec rake benchmark
```

