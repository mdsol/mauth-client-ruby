require 'base64'
require 'openssl'

module MAuth
  class Signer

    attr_reader :public_key, :private_key
    
    # Initialize with public or private key
    # Private key for encryption; public key for decryption
    # Keys should be passed in as strings
    def initialize(attrs = {})
      pub_key = attrs[:public_key] || attrs['public_key']
      priv_key = attrs[:private_key] || attrs['private_key']
      
      raise ArgumentError.new("must provide a public or private key") if pub_key.nil? && priv_key.nil?
      raise ArgumentError.new("public key must be a string") unless pub_key.nil? || pub_key.is_a?(String)
      raise ArgumentError.new("private key must be a string") unless priv_key.nil? || priv_key.is_a?(String)
      
      @public_key = OpenSSL::PKey::RSA.new(pub_key) unless pub_key.nil?
      @private_key = OpenSSL::PKey::RSA.new(priv_key) unless priv_key.nil?
    end

    # Returns a header to include in authenticated requests
    def signed_request_headers(params)
      params.merge!(:time => Time.now.to_i)
      {
        'Authorization' => "MWS #{params[:app_uuid]}:#{generate_request_signature(params)}",
        'x-mws-time' => params[:time].to_s
      }
    end

    # Generates a signature by encrypting string of request parameters
    def generate_request_signature(params)
      sig = encrypt_with_private_key format_string_to_sign_for_request(params)
      Base64.encode64(sig).gsub("\n","")
    end

    # Generate the string to sign for the request, composed of
    # request data concatentated and hashed
    def format_string_to_sign_for_request(params)
      require_param(params, :app_uuid, :verb, :request_url, :time)
      params[:post_data] = nil unless params.key?(:post_data)

      str_to_sign = [:verb, :request_url, :post_data, :app_uuid, :time].map {|key| params[key]}.join("\n")
      Digest::SHA512.hexdigest(str_to_sign)
    end

    # Verfiy that decrypted digest == encrypted params
    # and that signature time is within acceptable range
    def verify_request(signature, params)
      # Validate that params[:time] is within the last 5 minutes, or 5 minutes in the future
      valid_times = ((Time.now - 300).to_i..(Time.now + 300).to_i)
      unless !params[:time].nil? && valid_times.include?(params[:time].to_i)
        Rails.logger.info "Verfication failed: time outside valid range: #{params[:time]}" if defined?(Rails)
        return false
      end

      begin
        secure_compare(decrypt_with_public_key(Base64.decode64(signature)), format_string_to_sign_for_request(params))
      rescue OpenSSL::PKey::RSAError
        Rails.logger.error $!, $!.backtrace if defined?(Rails)
        false
      end
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

    # Encrypt hash of +string_to_encr+ with private key
    def encrypt_with_private_key(string_to_encr)
      private_key.private_encrypt(string_to_encr)
    end

    # Decrypt signature with public key
    def decrypt_with_public_key(signature)
      public_key.public_decrypt(signature)
    end
    
    # Raise unless all param requirements are met
    # Note:  post_data should not be included in keys
    def require_param(params, *keys)
      keys.each do |key|
        raise ArgumentError.new("Missing parameter #{key.inspect}") unless params.key?(key)
        raise ArgumentError.new("Missing value for #{key.inspect}") if params[key].nil? || (params[key].respond_to?(:empty?) && params[key].empty?)
      end
    end

  end
end
