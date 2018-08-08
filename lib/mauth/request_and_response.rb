require 'digest'

module MAuth
  # module which composes a string to sign.
  #
  # includer must provide
  # - SIGNATURE_COMPONENTS constant - array of keys to get from #attributes_for_signing
  # - #attributes_for_signing
  # - #merge_headers (takes a Hash of headers; returns an instance of includer's own class whose
  #   headers have been updated with the argument headers)
  module Signable
    # composes a string suitable for private-key signing from the SIGNATURE_COMPONENTS keys of
    # attributes for signing, which are themselves taken from #attributes_for_signing and
    # the given argument more_attributes
    def string_to_sign(more_attributes)
      attributes_for_signing = self.attributes_for_signing.merge(more_attributes)
      missing_attributes = self.class::SIGNATURE_COMPONENTS.select { |key| !attributes_for_signing.key?(key) || attributes_for_signing[key].nil? }
      missing_attributes.delete(:body) # body may be omitted
      if missing_attributes.any?
        raise(UnableToSignError, "Missing required attributes to sign: #{missing_attributes.inspect}\non object to sign: #{inspect}")
      end
      string = self.class::SIGNATURE_COMPONENTS.map { |k| attributes_for_signing[k].to_s }.join("\n")
      puts "components to sign #{string}"
      Digest::SHA512.hexdigest(string)
    end

    def initialize(attributes_for_signing)
      @attributes_for_signing = attributes_for_signing
    end

    def attributes_for_signing
      @attributes_for_signing
    end
  end

  # methods for an incoming object which is expected to have a signature.
  #
  # includer must provide
  # - #x_mws_authentication which returns that header's value
  # - #x_mws_time
  module Signed
    # returns a hash with keys :token, :app_uuid, and :signature parsed from the X-MWS-Authentication header
    def signature_info
      @signature_info ||= begin
        match = x_mws_authentication && x_mws_authentication.match(/\A([^ ]+) *([^:]+):([^:]+)\z/)
        match ? { token: match[1], app_uuid: match[2], signature: match[3] } : {}
      end
    end

    def signature_app_uuid
      signature_info[:app_uuid]
    end

    def signature_token
      signature_info[:token]
    end

    def signature
      signature_info[:signature]
    end
  end

  # virtual base class for signable requests
  class Request
    SIGNATURE_COMPONENTS = [:verb, :request_url, :body, :app_uuid, :time].freeze
    include Signable
  end

  # virtual base class for signable responses
  class Response
    SIGNATURE_COMPONENTS = [:status_code, :body, :app_uuid, :time].freeze
    include Signable
  end
end
