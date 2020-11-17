# Contributing

## Cloning the Repo

This repo contains the submodule `mauth-protocol-test-suite` so requires a flag when initially cloning in order to clone and init submodules.

With Git > 2.13

```
git clone --recurse-submodules git@github.com:mdsol/mauth-client-ruby.git
```

With Git < 2.13

```
git clone --recursive git@github.com:mdsol/mauth-client-ruby.git
```

If you have already cloned a version of this repo before the submodule was introduced in version 6.0.0 then run

```
cd spec/fixtures/mauth-protocol-test-suite
git submodule update --init
```

to init the submodule.

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

If you make changes which could affect performance, please run the benchmark before and after the change as a sanity check.

```
bundle exec rake benchmark
```
