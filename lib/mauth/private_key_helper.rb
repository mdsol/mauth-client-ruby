# frozen_string_literal: true

require 'openssl'

module MAuth
  module PrivateKeyHelper
    HEADER = '-----BEGIN RSA PRIVATE KEY-----'
    FOOTER = '-----END RSA PRIVATE KEY-----'

    module_function

    def generate
      OpenSSL::PKey::RSA.generate(2048)
    end

    def load(key)
      OpenSSL::PKey::RSA.new(to_rsa_format(key))
    rescue OpenSSL::PKey::RSAError
      raise 'The private key provided is invalid'
    end

    def to_rsa_format(key)
      return key if key.include?("\n")

      body = key.strip.delete_prefix(HEADER).delete_suffix(FOOTER).strip
      body = body.include?("\s") ? body.tr("\s", "\n") : body.scan(/.{1,64}/).join("\n")
      "#{HEADER}\n#{body}\n#{FOOTER}"
    end
  end
end
