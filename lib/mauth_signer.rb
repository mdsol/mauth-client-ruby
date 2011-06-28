module MAuth
  class Signer

    attr_reader :secret, :digest
    def initialize(secret)
      @secret = secret.to_s
      raise ArgumentError.new("secret cannot be empty") if @secret.empty?

      @digest = 'SHA1'
    end

    # Returns a header to include in authenticated requests
    def signed_headers(app_uuid, verb, request_url, post_data=nil)
      time = Time.now.to_i
      {
        'Authorization' => "MWS #{app_uuid}:#{generate_signature(app_uuid, verb, request_url, time, post_data)}",
        'x-mws-time' => time.to_s
      }
    end

    # Generates an HMAC from request parameters
    def generate_signature(app_uuid, verb, request_url, time, post_data=nil)
      generate_digest format_string_to_sign(app_uuid, verb, request_url, time, post_data)
    end

    def format_string_to_sign(app_uuid, verb, request_url, time, post_data)
      [verb, request_url, post_data, app_uuid, time].join("\n")
    end

    # constant-time comparison algorithm to prevent timing attacks
    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      l = a.unpack "C#{a.bytesize}"

      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res == 0
    end

    private
    # Generates an HMAC for +data+
    def generate_digest(data)
      require 'openssl' unless defined?(OpenSSL)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest.const_get(digest).new, secret, data)
    end

  end
end
