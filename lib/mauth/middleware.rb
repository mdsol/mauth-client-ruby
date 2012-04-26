require 'mauth/core_ext'
module MAuth
  # base class for middleware, common to both Faraday and Rack
  class Middleware
    def initialize(app, config={})
      @app = app
      # stringify symbol keys
      @config = config.stringify_symbol_keys
    end
    # returns a MAuth::Client - if one was given as 'mauth_client' when initializing the 
    # middleware, then that one; otherwise the configurationg given to initialize the 
    # middleware is passed along to make a new MAuth::Client. 
    #
    # this method may be overloaded to provide more flexibility in providing a MAuth::Client 
    def mauth_client
      require 'mauth/client'
      # @_mauth_client ivar only used here for caching; should not be used by other methods, in 
      # order that overloading #mauth_client will work 
      @_mauth_client ||= @config['mauth_client'] || MAuth::Client.new(@config)
    end
  end
end
