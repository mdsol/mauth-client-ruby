require 'mauth/core_ext'
module Mauth
  # base class for middleware, common to both Faraday and Rack
  class Middleware
    def initialize(app, config = {})
      @app = app
      # stringify symbol keys
      @config = config.stringify_symbol_keys
    end

    # returns a Mauth::Client - if one was given as 'mauth_client' when initializing the
    # middleware, then that one; otherwise the configurationg given to initialize the
    # middleware is passed along to make a new Mauth::Client.
    #
    # this method may be overloaded to provide more flexibility in providing a Mauth::Client
    def mauth_client
      require 'mauth/client'
      # @_mauth_client ivar only used here for caching; should not be used by other methods, in
      # order that overloading #mauth_client will work
      @_mauth_client ||= @config['mauth_client'] || Mauth::Client.new(@config)
    end
  end
end
