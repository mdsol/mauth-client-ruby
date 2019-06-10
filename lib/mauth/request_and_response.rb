require 'digest'

module MAuth
  # module which composes a string to sign.
  #
  # includer must provide
  # - SIGNATURE_COMPONENTS OR SIGNATURE_COMPONENTS_V2 constant - array of keys to get from #attributes_for_signing
  # - #attributes_for_signing
  # - #merge_headers (takes a Hash of headers; returns an instance of includer's own class whose
  #   headers have been updated with the argument headers)
  module Signable
    # composes a string suitable for private-key signing from the SIGNATURE_COMPONENTS keys of
    # attributes for signing, which are themselves taken from #attributes_for_signing and
    # the given argument more_attributes

    # the string to sign for V1 protocol will be (where LF is line feed character)
    # for requests:
    #   string_to_sign =
    #     http_verb + <LF> +
    #     resource_url_path (no host, port or query string; first "/" is included) + <LF> +
    #     request_body + <LF> +
    #     app_uuid + <LF> +
    #     current_seconds_since_epoch + <LF> +
    #
    # for responses:
    #   string_to_sign =
    #     status_code_string + <LF> +
    #     response_body_digest + <LF> +
    #     app_uuid + <LF> +
    #     current_seconds_since_epoch
    def string_to_sign_v1(more_attributes)
      attributes_for_signing = self.attributes_for_signing.merge(more_attributes)
      missing_attributes = self.class::SIGNATURE_COMPONENTS.select { |key| !attributes_for_signing.key?(key) || attributes_for_signing[key].nil? }
      missing_attributes.delete(:body) # body may be omitted
      if missing_attributes.any?
        raise(UnableToSignError, "Missing required attributes to sign: #{missing_attributes.inspect}\non object to sign: #{inspect}")
      end
      string = self.class::SIGNATURE_COMPONENTS.map { |k| attributes_for_signing[k].to_s }.join("\n")
      Digest::SHA512.hexdigest(string)
    end

    # the string to sign for V2 protocol will be (where LF is line feed character)
    # for requests:
    #   string_to_sign =
    #     http_verb + <LF> +
    #     resource_url_path (no host, port or query string; first "/" is included) + <LF> +
    #     request_body_digest + <LF> +
    #     app_uuid + <LF> +
    #     current_seconds_since_epoch + <LF> +
    #     encoded_query_params
    #
    # for responses:
    #   string_to_sign =
    #     status_code_string + <LF> +
    #     response_body_digest + <LF> +
    #     app_uuid + <LF> +
    #     current_seconds_since_epoch
    def string_to_sign_v2(more_attributes)
      attributes_for_signing = self.attributes_for_signing.merge(more_attributes)

      # lazy instantiation of body digest to avoid hashing request bodies
      # three times because we call string to sign three times.
      if attributes_for_signing[:body]
        attributes_for_signing[:body_digest] ||= Digest::SHA512.hexdigest(attributes_for_signing[:body].to_s)
      end
      attributes_for_signing[:encoded_query_params] = encode_query_string(attributes_for_signing[:query_string].to_s)

      missing_attributes = self.class::SIGNATURE_COMPONENTS_V2.reject do |key|
        attributes_for_signing.dig(key)
      end

      missing_attributes.delete(:body_digest) # body may be omitted
      if missing_attributes.any?
        raise(UnableToSignError, "Missing required attributes to sign: #{missing_attributes.inspect}\non object to sign: #{inspect}")
      end

      string = self.class::SIGNATURE_COMPONENTS_V2.map do |k|
        attributes_for_signing[k].to_s.force_encoding('UTF-8')
      end.join("\n")
      Digest::SHA512.hexdigest(string)
    end

    # sorts query string parameters by codepoint, uri encodes keys and values,
    # and rejoins parameters into a query string
    # Note: must sort query params using a stable sort because multiple parameters
    # with the same key muyst appear in the same order when signing and authenticating.
    # todo this sort is stable but probably slow. merge sort? stable quick sort?
    def encode_query_string(q_string)
      q_string.split('&').sort_by.with_index { |x, idx| [x, idx] }.map do |part|
        k, e, v = part.partition('=')
        uri_escape(k) + e + uri_escape(v)
      end.join('&')
    end

    # percent encodes special characters, preserving character encoding
    # identical to CGI.escape except it encodes spaces as %20%
    # QUESTION should just use CGI.escape then gsub?
    # CGI.escape(string).gsub!(/\+/, '%20%')
    def uri_escape(string)
      encoding = string.encoding
      string.b.gsub(/([^a-zA-Z0-9_.~-]+)/) do |m|
        '%' + m.unpack('H2' * m.bytesize).join('%').upcase
      end.force_encoding(encoding)
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
  # - #mcc_authentication which returns that header's value
  # - #mcc_time
  # OR
  # - #x_mws_authentication which returns that header's value
  # - #x_mws_time
  module Signed
    # mauth_client will authenticate with the highest protocol version present and ignore other
    # protocol versions.
    # returns a hash with keys :token, :app_uuid, and :signature parsed from the MCC-Authentication header
    # if it is present and if not then the X-MWS-Authentication header if it is present.
    # Note MWSV2 protocol no longer allows more than one space between the token and app uuid.
    def signature_info
      @signature_info ||= begin
        match = if mcc_authentication
          mcc_authentication.match(
            /\A(#{MAuth::Client::MWSV2_TOKEN}) ([^:]+):([^:]+)#{MAuth::Client::AUTH_HEADER_DELIMITER}\z/
          )
        elsif x_mws_authentication
          x_mws_authentication.match(/\A([^ ]+) *([^:]+):([^:]+)\z/)
        end

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
    SIGNATURE_COMPONENTS = %i[verb request_url body app_uuid time].freeze
    SIGNATURE_COMPONENTS_V2 =
      %i[
        verb
        request_url
        body_digest
        app_uuid
        time
        encoded_query_params
      ].freeze

    include Signable
  end

  # virtual base class for signable responses
  class Response
    SIGNATURE_COMPONENTS = %i[status_code body app_uuid time].freeze
    SIGNATURE_COMPONENTS_V2 = %i[status_code body_digest app_uuid time].freeze
    include Signable
  end
end
