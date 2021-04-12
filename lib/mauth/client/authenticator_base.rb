# methods common to RemoteRequestAuthenticator and LocalAuthenticator

module Mauth
  class Client
    module AuthenticatorBase
      ALLOWED_DRIFT_SECONDS = 300

      # takes an incoming request or response object, and returns whether
      # the object is authentic according to its signature.
      def authentic?(object)
        log_authentication_request(object)
        begin
          authenticate!(object)
          true
        rescue InauthenticError, MauthNotPresent, MissingV2Error
          false
        end
      end

      # raises InauthenticError unless the given object is authentic. Will only
      # authenticate with v2 if the environment variable V2_ONLY_AUTHENTICATE
      # is set. Otherwise will fall back to v1 when v2 authentication fails
      def authenticate!(object)
        if object.protocol_version == 2
          begin
            authenticate_v2!(object)
          rescue InauthenticError => e
            raise e if v2_only_authenticate?
            raise e if disable_fallback_to_v1_on_v2_failure?

            object.fall_back_to_mws_signature_info
            raise e unless object.signature

            log_authentication_request(object)
            authenticate_v1!(object)
            logger.warn("Completed successful authentication attempt after fallback to v1")
          end
        elsif object.protocol_version == 1
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
          raise MauthNotPresent, msg
        end
      end

      private

      # Note: This log is likely consumed downstream and the contents SHOULD NOT
      # be changed without a thorough review of downstream consumers.
      def log_authentication_request(object)
        object_app_uuid = object.signature_app_uuid || '[none provided]'
        object_token = object.signature_token || '[none provided]'
        logger.info(
          "Mauth-client attempting to authenticate request from app with mauth" \
          " app uuid #{object_app_uuid} to app with mauth app uuid #{client_app_uuid}" \
          " using version #{object_token}."
        )
      end

      def log_inauthentic(object, message)
        logger.error("mAuth signature authentication failed for #{object.class}. Exception: #{message}")
      end

      def time_within_valid_range!(object, time_signed, now = Time.now)
        return if  (-ALLOWED_DRIFT_SECONDS..ALLOWED_DRIFT_SECONDS).cover?(now.to_i - time_signed)

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
    end
  end
end
