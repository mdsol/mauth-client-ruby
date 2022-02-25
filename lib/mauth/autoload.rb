# frozen_string_literal: true

module MAuth
  autoload :Client, 'mauth/client'
  autoload :Middleware, 'mauth/middleware'
  autoload :Faraday, 'mauth/faraday'
  autoload :Rack, 'mauth/rack'
  autoload :Request, 'mauth/request_and_response'
  autoload :Response, 'mauth/request_and_response'
end
