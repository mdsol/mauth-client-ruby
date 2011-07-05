module MAuth
  class Signer

    attr_reader :secret, :digest
    def initialize(secret)
      @secret = secret.to_s
      raise ArgumentError.new("secret cannot be empty") if @secret.empty?

      @digest = 'SHA1'
    end

    # Returns a header to include in authenticated requests
    def signed_headers(params)
      params.merge!(:time => Time.now.to_i)
      {
        'Authorization' => "MWS #{params[:app_uuid]}:#{generate_signature(params)}",
        'x-mws-time' => params[:time].to_s
      }
    end

    # Generates an HMAC from request parameters
    def generate_signature(params)
      generate_digest format_string_to_sign(params)
    end

    def format_string_to_sign(params)
      require_param(params, :app_uuid, :verb, :request_url, :time)
      params[:post_data] = nil unless params.key?(:post_data)

      [:verb, :request_url, :post_data, :app_uuid, :time].map {|key| params[key]}.join("\n")
    end

    def verify(digest, params)
      # Validate that params[:time] is within the last 15 minutes, or 1 minute in the future
      valid_times = ((Time.now - 900).to_i..(Time.now.to_i + 60))
      unless valid_times.include?(params[:time].to_i)
        Rails.logger.info "Verfication failed: time outside valid range: #{params[:time]}" if defined?(Rails)
        return false
      end

      secure_compare(digest, generate_signature(params))
    end

    private
    # constant-time comparison algorithm to prevent timing attacks
    # Copied from https://github.com/rails/rails/blob/b31ce90e99ca73ebbe52/activesupport/lib/active_support/message_verifier.rb
    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      l = a.unpack "C#{a.bytesize}"

      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res == 0
    end

    # Generates an HMAC for +data+
    def generate_digest(data)
      require 'openssl' unless defined?(OpenSSL)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest.const_get(digest).new, secret, data)
    end

    def require_param(params, *keys)
      keys.each do |key|
        raise ArgumentError.new("Missing parameter #{key.inspect}") unless params.key?(key)
      end
    end

  end
end
