# frozen_string_literal: true

require 'mauth/client/security_token_cacher'
require 'mauth/client/signer'
require 'openssl'

# methods to verify the authenticity of signed requests and responses

module MAuth
  class Client
    module Authenticator
      ALLOWED_DRIFT_SECONDS = 300

      # takes an incoming request or response object, and returns whether
      # the object is authentic according to its signature.
      def authentic?(object)
        log_authentication_request(object)
        begin
          authenticate!(object)
          true
        rescue InauthenticError, MAuthNotPresent, MissingV2Error
          false
        end
      end

      # raises InauthenticError unless the given object is authentic. Will only
      # authenticate with v2 if the environment variable V2_ONLY_AUTHENTICATE
      # is set. Otherwise will fall back to v1 when v2 authentication fails
      def authenticate!(object)
        case object.protocol_version
        when 2
          begin
            authenticate_v2!(object)
          rescue InauthenticError => e
            raise e if v2_only_authenticate?
            raise e if disable_fallback_to_v1_on_v2_failure?

            object.fall_back_to_mws_signature_info
            raise e unless object.signature

            log_authentication_request(object)
            authenticate_v1!(object)
            logger.warn('Completed successful authentication attempt after fallback to v1')
          end
        when 1
          if v2_only_authenticate?
            # If v2 is required but not present and v1 is present we raise MissingV2Error
            msg = 'This service requires mAuth v2 mcc-authentication header but only v1 x-mws-authentication is present'
            logger.error(msg)
            raise MissingV2Error, msg
          end

          authenticate_v1!(object)
        else
          sub_str = v2_only_authenticate? ? '' : 'X-MWS-Authentication header is blank, '
          msg = "Authentication Failed. No mAuth signature present; #{sub_str}MCC-Authentication header is blank."
          logger.warn("mAuth signature not present on #{object.class}. Exception: #{msg}")
          raise MAuthNotPresent, msg
        end
      end

      private

      # NOTE: This log is likely consumed downstream and the contents SHOULD NOT
      # be changed without a thorough review of downstream consumers.
      def log_authentication_request(object)
        object_app_uuid = object.signature_app_uuid || '[none provided]'
        object_token = object.signature_token || '[none provided]'
        logger.info(
          'Mauth-client attempting to authenticate request from app with mauth ' \
          "app uuid #{object_app_uuid} to app with mauth app uuid #{client_app_uuid} " \
          "using version #{object_token}."
        )
      end

      def log_inauthentic(object, message)
        logger.error("mAuth signature authentication failed for #{object.class}. Exception: #{message}")
      end

      def time_within_valid_range!(object, time_signed, now = Time.now)
        return if (-ALLOWED_DRIFT_SECONDS..ALLOWED_DRIFT_SECONDS).cover?(now.to_i - time_signed)

        msg = "Time verification failed. #{time_signed} not within #{ALLOWED_DRIFT_SECONDS} of #{now}"
        log_inauthentic(object, msg)
        raise InauthenticError, msg
      end

      # V1 helpers
      def authenticate_v1!(object)
        time_valid_v1!(object)
        token_valid_v1!(object)
        signature_valid_v1!(object)
      end

      def time_valid_v1!(object)
        if object.x_mws_time.nil?
          msg = 'Time verification failed. No x-mws-time present.'
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
        time_within_valid_range!(object, object.x_mws_time.to_i)
      end

      def token_valid_v1!(object)
        return if object.signature_token == MWS_TOKEN

        msg = "Token verification failed. Expected #{MWS_TOKEN}; token was #{object.signature_token}"
        log_inauthentic(object, msg)
        raise InauthenticError, msg
      end

      # V2 helpers
      def authenticate_v2!(object)
        time_valid_v2!(object)
        token_valid_v2!(object)
        signature_valid_v2!(object)
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
        expected_for_percent_reencoding = object.string_to_sign_v1(time: object.x_mws_time,
          app_uuid: object.signature_app_uuid)

        # do a moderately complex Euresource-style reencoding of the path
        object.attributes_for_signing[:request_url] = euresource_escape(original_request_uri.to_s)
        expected_euresource_style_reencoding = object.string_to_sign_v1(time: object.x_mws_time,
          app_uuid: object.signature_app_uuid)

        # reset the object original request_uri, just in case we need it again
        object.attributes_for_signing[:request_url] = original_request_uri

        begin
          pubkey = OpenSSL::PKey::RSA.new(retrieve_public_key(object.signature_app_uuid))
          actual = pubkey.public_decrypt(Base64.decode64(object.signature))
        rescue OpenSSL::PKey::PKeyError => e
          msg = "Public key decryption of signature failed! #{e.class}: #{e.message}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end

        unless verify_signature_v1!(actual, expected_no_reencoding) ||
               verify_signature_v1!(actual, expected_euresource_style_reencoding) ||
               verify_signature_v1!(actual, expected_for_percent_reencoding)
          msg = "Signature verification failed for #{object.class}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
      end

      def verify_signature_v1!(actual, expected_str_to_sign)
        actual == OpenSSL::Digest::SHA512.hexdigest(expected_str_to_sign)
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
          query_string: euresource_query_escape(original_query_string.to_s)
        )

        pubkey = OpenSSL::PKey::RSA.new(retrieve_public_key(object.signature_app_uuid))
        actual = Base64.decode64(object.signature)

        unless verify_signature_v2!(object, actual, pubkey, expected_no_reencoding) ||
               verify_signature_v2!(object, actual, pubkey, expected_euresource_style_reencoding) ||
               verify_signature_v2!(object, actual, pubkey, expected_for_percent_reencoding)
          msg = "Signature inauthentic for #{object.class}"
          log_inauthentic(object, msg)
          raise InauthenticError, msg
        end
      end

      def verify_signature_v2!(object, actual, pubkey, expected_str_to_sign)
        pubkey.verify(
          MAuth::Client::SIGNING_DIGEST,
          actual,
          expected_str_to_sign
        )
      rescue OpenSSL::PKey::PKeyError => e
        msg = "RSA verification of signature failed! #{e.class}: #{e.message}"
        log_inauthentic(object, msg)
        raise InauthenticError, msg
      end

      # NOTE: RFC 3986 (https://www.ietf.org/rfc/rfc3986.txt) reserves the forward slash "/"
      #   and number sign "#" as component delimiters. Since these are valid URI components,
      #   they are decoded back into characters here to avoid signature invalidation
      def euresource_escape(str)
        CGI.escape(str).gsub(/%2F|%23/, '%2F' => '/', '%23' => '#')
      end

      # Euresource encodes keys and values of query params but does not encode the '='
      # that separates keys and values and the '&' that separate k/v pairs
      # Euresource currently adds query parameters via the following method:
      # https://www.rubydoc.info/gems/addressable/2.3.4/Addressable/URI#query_values=-instance_method
      def euresource_query_escape(str)
        CGI.escape(str).gsub(/%3D|%26/, '%3D' => '=', '%26' => '&')
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
