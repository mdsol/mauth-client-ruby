# contains methods for MWSV2

module MAuth
  class Client
    MWSV2_TOKEN = 'MWSV2'.freeze
    AUTH_HEADER_DELIMITER = ';'.freeze

    # methods to sign requests and responses. part of MAuth::Client
    module Signer
      def signed_v2(object, attributes = {})
        object.merge_headers(signed_headers_v2(object, attributes))
      end

      def signed_headers_v2(object, attributes = {})
        attributes = { time: Time.now.to_i.to_s, app_uuid: client_app_uuid }.merge(attributes)
        string_to_sign = object.string_to_sign_v2(attributes)
        signature = self.signature(string_to_sign)
        {
          'MCC-Authentication' => "#{MWSV2_TOKEN} #{client_app_uuid}:#{signature}#{AUTH_HEADER_DELIMITER}",
          'MCC-Time' => attributes[:time]
        }
      end
    end
    include Signer

    # methods common to RemoteRequestAuthenticator and LocalAuthenticator
    module Authenticator
      private

      def authenticate_v2!(object)
        time_valid_v2!(object)
        token_valid_v2!(object)
        signature_valid_v2!(object)
      end

      def authentication_present_v2?(object)
        !object.mcc_authentication.to_s.strip.empty?
      end

      def time_valid_v2!(object)
        if object.mcc_time.nil?
          msg = 'Time verification failed. No MCC-Time present.'
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
        time_within_valid_range!(object, object.mcc_time.to_i)
      end

      def token_valid_v2!(object)
        return if object.signature_token == MWSV2_TOKEN

        msg = "Token verification failed. Expected #{MWSV2_TOKEN}; token was #{object.signature_token}"
        log_inauthentic(object, msg)
        raise InauthenticError, msg
      end
    end
    include Authenticator

    # methods to verify the authenticity of signed requests and responses locally, retrieving
    # public keys from the mAuth service as needed
    module LocalAuthenticator
      private

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

        actual = actual_string_to_sign(object)

        unless expected_no_reencoding == actual ||
           expected_euresource_style_reencoding == actual ||
           expected_for_percent_reencoding == actual
          msg = "Signature verification failed for #{object.class}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
      end

      def actual_string_to_sign(object)
        pubkey = OpenSSL::PKey::RSA.new(retrieve_public_key(object.signature_app_uuid))

        begin
          pubkey.public_decrypt(Base64.decode64(object.signature))
        rescue OpenSSL::PKey::PKeyError => e
          msg = "Public key decryption of signature failed! #{e.class}: #{e.message}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
      end
    end

    # methods for remotely authenticating a request by sending it to the mauth service
    module RemoteRequestAuthenticator
      private

      # TODO: update mAuth to be able verify authentication tickets w V2 (MCC-413109)
      def signature_valid_v2!(object)
        unless object.is_a?(MAuth::Request)
          msg = "Remote Authenticator can only authenticate requests; received #{object.inspect}"
          raise ArgumentError, msg
        end

        authentication_ticket = {
          verb: object.attributes_for_signing[:verb],
          app_uuid: object.signature_app_uuid,
          client_signature: object.signature,
          request_url: object.attributes_for_signing[:request_url],
          request_time: object.mcc_time,
          b64encoded_body: Base64.encode64(object.attributes_for_signing[:body] || ''),
          query_string: object.attributes_for_signing[:query_string],
          token: object.signature_token
        }
        make_mauth_request(authentication_ticket)
      end
    end
  end
end
