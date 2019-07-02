require 'mauth/client/security_token_cacher'

# methods to verify the authenticity of signed requests and responses locally, retrieving
# public keys from the mAuth service as needed

module MAuth
  class Client
    module LocalAuthenticator
      private

      def signature_valid_v1!(object)
        # We are in an unfortunate situation in which Euresource is percent-encoding parts of paths, but not
        # all of them.  In particular, Euresource is percent-encoding all special characters save for '/'.
        # Also, unfortunately, Nginx unencodes URIs before sending them off to served applications, though
        # other web servers (particularly those we typically use for local testing) do not.  The various forms
        # of the expected string to sign are meant to cover the main cases.
        # TODO:  Revisit and simplify this unfortunate situation.

        original_request_uri = object.attributes_for_signing[:request_url]

        # craft an expected string-to-sign without doing any percent-encoding
        expected_no_reencoding = object.string_to_sign_v1(time: object.x_mws_time, app_uuid: object.signature_app_uuid)

        # do a simple percent reencoding variant of the path
        object.attributes_for_signing[:request_url] = CGI.escape(original_request_uri.to_s)
        expected_for_percent_reencoding = object.string_to_sign_v1(time: object.x_mws_time, app_uuid: object.signature_app_uuid)

        # do a moderately complex Euresource-style reencoding of the path
        object.attributes_for_signing[:request_url] = euresource_escape(original_request_uri.to_s)
        expected_euresource_style_reencoding = object.string_to_sign_v1(time: object.x_mws_time, app_uuid: object.signature_app_uuid)

        # reset the object original request_uri, just in case we need it again
        object.attributes_for_signing[:request_url] = original_request_uri

        pubkey = OpenSSL::PKey::RSA.new(retrieve_public_key(object.signature_app_uuid))
        begin
          actual = pubkey.public_decrypt(Base64.decode64(object.signature))
        rescue OpenSSL::PKey::PKeyError => e
          msg = "Public key decryption of signature failed! #{e.class}: #{e.message}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end

        unless expected_no_reencoding == actual || expected_euresource_style_reencoding == actual || expected_for_percent_reencoding == actual
          msg = "Signature verification failed for #{object.class}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
      end

      def signature_valid_v2!(object)
        # We are in an unfortunate situation in which Euresource is percent-encoding parts of paths, but not
        # all of them.  In particular, Euresource is percent-encoding all special characters save for '/'.
        # Also, unfortunately, Nginx unencodes URIs before sending them off to served applications, though
        # other web servers (particularly those we typically use for local testing) do not.  The various forms
        # of the expected string to sign are meant to cover the main cases.
        # TODO:  Revisit and simplify this unfortunate situation.

        original_request_uri = object.attributes_for_signing[:request_url]
        original_query_string = object.attributes_for_signing[:query_string]

        # craft an expected string-to-sign without doing any percent-encoding
        expected_no_reencoding = object.string_to_sign_v2(
          time: object.mcc_time,
          app_uuid: object.signature_app_uuid
        )

        # do a simple percent reencoding variant of the path
        expected_for_percent_reencoding = object.string_to_sign_v2(
          time: object.mcc_time,
          app_uuid: object.signature_app_uuid,
          request_url: CGI.escape(original_request_uri.to_s),
          query_string: CGI.escape(original_query_string.to_s)
        )

        # do a moderately complex Euresource-style reencoding of the path
        expected_euresource_style_reencoding = object.string_to_sign_v2(
          time: object.mcc_time,
          app_uuid: object.signature_app_uuid,
          request_url: euresource_escape(original_request_uri.to_s),
          query_string: euresource_escape(original_query_string.to_s)
        )

        unless verify_signature!(object, expected_no_reencoding) ||
           verify_signature!(object, expected_euresource_style_reencoding) ||
           verify_signature!(object, expected_for_percent_reencoding)
          msg = "Signature verification failed for #{object.class}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
      end

      def verify_signature!(object, data)
        pubkey = OpenSSL::PKey::RSA.new(retrieve_public_key(object.signature_app_uuid))
        digest = OpenSSL::Digest::SHA256.new

        begin
          pubkey.verify(digest, Base64.decode64(object.signature), data)
        rescue OpenSSL::PKey::PKeyError => e
          msg = "Public key decryption of signature failed! #{e.class}: #{e.message}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
      end

      # Note: RFC 3986 (https://www.ietf.org/rfc/rfc3986.txt) reserves the forward slash "/"
      #   and number sign "#" as component delimiters. Since these are valid URI components,
      #   they are decoded back into characters here to avoid signature invalidation
      def euresource_escape(str)
        CGI.escape(str).gsub(/%2F|%23/, '%2F' => '/', '%23' => '#')
      end

      def retrieve_public_key(app_uuid)
        retrieve_security_token(app_uuid)['security_token']['public_key_str']
      end

      def retrieve_security_token(app_uuid)
        security_token_cacher.get(app_uuid)
      end

      def security_token_cacher
        @security_token_cacher ||= SecurityTokenCacher.new(self)
      end

    end
  end
end
