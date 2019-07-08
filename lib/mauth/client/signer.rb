require 'openssl'

# methods to sign requests and responses. part of MAuth::Client

module MAuth
  class Client
    module Signer
      SIGNING_DIGEST = OpenSSL::Digest::SHA512.new

      # takes an outgoing request or response object, and returns an object of the same class
      # whose headers are updated to include mauth's signature headers
      def signed(object, attributes = {})
        object.merge_headers(signed_headers(object, attributes))
      end

      # signs with v1 only. used when signing responses to v1 requests.
      def signed_v1(object, attributes = {})
        object.merge_headers(signed_headers_v1(object, attributes))
      end

      def signed_v2(object, attributes = {})
        object.merge_headers(signed_headers_v2(object, attributes))
      end

      # takes a signable object (outgoing request or response). returns a hash of headers to be
      # applied to the object which comprises its signature.
      def signed_headers(object, attributes = {})
        if v2_only_sign_requests?
          signed_headers_v2(object, attributes)
        else # by default sign with both the v1 and v2 protocol
          signed_headers_v1(object, attributes).merge(signed_headers_v2(object, attributes))
        end
      end

      def signed_headers_v1(object, attributes = {})
        attributes = { time: Time.now.to_i.to_s, app_uuid: client_app_uuid }.merge(attributes)
        hashed_string_to_sign = object.string_to_sign_v1(attributes)
        signature = self.signature_v1(hashed_string_to_sign)
        { 'X-MWS-Authentication' => "#{MWS_TOKEN} #{client_app_uuid}:#{signature}", 'X-MWS-Time' => attributes[:time] }
      end

      def signed_headers_v2(object, attributes = {})
        attributes = { time: Time.now.to_i.to_s, app_uuid: client_app_uuid }.merge(attributes)
        string_to_sign = object.string_to_sign_v2(attributes)
        signature = self.signature_v2(string_to_sign)
        {
          'MCC-Authentication' => "#{MWSV2_TOKEN} #{client_app_uuid}:#{signature}#{AUTH_HEADER_DELIMITER}",
          'MCC-Time' => attributes[:time]
        }
      end

      def signature_v1(string_to_sign)
        assert_private_key(UnableToSignError.new('mAuth client cannot sign without a private key!'))
        Base64.encode64(private_key.private_encrypt(string_to_sign)).delete("\n")
      end

      def signature_v2(string_to_sign)
        assert_private_key(UnableToSignError.new('mAuth client cannot sign without a private key!'))
        Base64.encode64(private_key.sign(SIGNING_DIGEST, string_to_sign)).delete("\n")
      end
    end
  end
end
