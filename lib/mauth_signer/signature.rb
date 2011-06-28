module MAuth
  class Signature < String

    def initialize(http_verb, requested_url, post_data, mws_access_key_id, secret_access_key)
      super()
      @request, @mws_access_key_id, @secret_access_key = request, mws_access_key_id, secret_access_key
      self << encoded_canonical 
    end

    private

    def canonical_string
      CanonicalString.new(request)
    end
    memoized :canonical_string

    def encoded_canonical
      digest   = OpenSSL::Digest::Digest.new('sha1')
      b64_hmac = [OpenSSL::HMAC.digest(digest, secret_access_key, canonical_string)].pack("m").strip
      b64_hmac
    end

  end

  class Header < String
    def initialize(http_verb, requested_url, post_data)
      super
      self << "MWS #{mws_access_key_id}:#{encoded_canonical}"
    end
  end
end
