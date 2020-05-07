require 'digest'
require 'addressable'

module MAuth
  # module which composes a string to sign.
  #
  # includer must provide
  # - SIGNATURE_COMPONENTS OR SIGNATURE_COMPONENTS_V2 constant - array of keys to get from
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
    #     current_seconds_since_epoch
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
      self.class::SIGNATURE_COMPONENTS.map { |k| attributes_for_signing[k].to_s }.join("\n")
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
    def string_to_sign_v2(override_attrs)
      attrs_with_overrides = self.attributes_for_signing.merge(override_attrs)

      # memoization of body_digest to avoid hashing three times when we call
      # string_to_sign_v2 three times in client#signature_valid_v2!
      # note that if :body is nil we hash an empty string ('')
      attrs_with_overrides[:body_digest] ||= Digest::SHA512.hexdigest(attrs_with_overrides[:body] || '')
      attrs_with_overrides[:encoded_query_params] = unescape_encode_query_string(attrs_with_overrides[:query_string] || '')
      attrs_with_overrides[:request_url] = normalize_path(attrs_with_overrides[:request_url])

      missing_attributes = self.class::SIGNATURE_COMPONENTS_V2.reject do |key|
        attrs_with_overrides.dig(key)
      end

      missing_attributes.delete(:body_digest) # body may be omitted
      missing_attributes.delete(:encoded_query_params) # query_string may be omitted
      if missing_attributes.any?
        raise(UnableToSignError, "Missing required attributes to sign: #{missing_attributes.inspect}\non object to sign: #{inspect}")
      end

      self.class::SIGNATURE_COMPONENTS_V2.map do |k|
        attrs_with_overrides[k].to_s.dup.force_encoding('UTF-8')
      end.join("\n")
    end

    # Addressable::URI.parse(path).normalize.to_s.squeeze('/')
    def normalize_path(path)
      return if path.nil?

      # Addressable::URI.normalize_path normalizes `.` and `..` in path
      #   i.e. /./example => /example ; /example/.. => /
      # String#squeeze removes duplicated slahes i.e. /// => /
      # String#gsub normalizes percent encoding to uppercase i.e. %cf%80 => %CF%80
      Addressable::URI.normalize_path(path).squeeze('/').
        gsub(/%[a-f0-9]{2}/, &:upcase)
    end

    # sorts query string parameters by codepoint, uri encodes keys and values,
    # and rejoins parameters into a query string
    def unescape_encode_query_string(q_string)
      fir = q_string.split('&').map do |part|
        k, _eq, v = part.partition('=')
        [CGI.unescape(k), CGI.unescape(v)]
      end.sort.map do |k, v|
        "#{uri_escape(k)}=#{uri_escape(v)}"
      end.join('&')
    end

    # percent encodes special characters, preserving character encoding.
    # encodes space as '%20'
    # does not encode A-Z, a-z, 0-9, hyphen ( - ), underscore ( _ ), period ( . ),
    # or tilde ( ~ )
    # NOTE the CGI.escape spec changed in 2.5 to not escape tildes. we gsub
    # tilde encoding back to tildes to account for older Rubies
    def uri_escape(string)
      CGI.escape(string).gsub(/\+|%7E/, '+' => '%20', '%7E' => '~')
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
    # mauth_client will authenticate with the highest protocol version present and if authentication fails,
    # will fall back to lower protocol versions (if provided).
    # returns a hash with keys :token, :app_uuid, and :signature parsed from the MCC-Authentication header
    # if it is present and if not then the X-MWS-Authentication header if it is present.
    # Note MWSV2 protocol no longer allows more than one space between the token and app uuid.
    def signature_info
      @signature_info ||= build_signature_info(mcc_data || x_mws_data)
    end

    def fall_back_to_mws_signature_info
      @signature_info = build_signature_info(x_mws_data)
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

    def protocol_version
      if !mcc_authentication.to_s.strip.empty?
        2
      elsif !x_mws_authentication.to_s.strip.empty?
        1
      end
    end

    private

    def build_signature_info(match_data)
      match_data ? { token: match_data[1], app_uuid: match_data[2], signature: match_data[3] } : {}
    end

    def mcc_data
      mcc_authentication&.match(
        /\A(#{MAuth::Client::MWSV2_TOKEN}) ([^:]+):([^:]+)#{MAuth::Client::AUTH_HEADER_DELIMITER}\z/
      )
    end

    def x_mws_data
      x_mws_authentication&.match(/\A([^ ]+) *([^:]+):([^:]+)\z/)
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
