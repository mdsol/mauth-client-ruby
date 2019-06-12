# methods common to RemoteRequestAuthenticator and LocalAuthenticator

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
        rescue InauthenticError, MauthNotPresent
          false
        end
      end

      # raises InauthenticError unless the given object is authentic. Will only
      # authenticate with v2 if the environment variable AUTHENTICATE_WITH_ONLY_V2
      # is set. Otherwise will authenticate with only the highest protocol version present
      def authenticate!(object)
        if authenticate_with_only_v2? && authentication_present_v1(object)
          msg = 'This service requires mAuth v2 mcc-authentication header but only v1 x-mws-authentication is present'
          log_inauthentic(object, msg)
          raise MAuth::MissingV2Error, msg
        elsif authenticate_with_only_v2?
          authentication_present_v2!(object)
          authenticate_v2!(object)
        elsif authentication_present_v2(object)
          authenticate_v2!(object)
        elsif authentication_present_v1(object)
          authenticate_v1!(object)
        else
          msg = 'Authentication Failed. No mAuth signature present;  X-MWS-Authentication header is blank, MCC-Authentication header is blank.'
          log_inauthentic(object, msg)
          raise MauthNotPresent, msg
        end
      end

      private

      # Note: This log is likely consumed downstream and the contents SHOULD NOT be changed without a thorough review of downstream consumers.
      def log_authentication_request(object)
        object_app_uuid = object.signature_app_uuid || '[none provided]'
        object_token = object.signature_token || '[none provided]'
        logger.info "Mauth-client attempting to authenticate request from app with mauth app uuid #{object_app_uuid} to app with mauth app uuid #{client_app_uuid} using version #{object_token}."
      end

      def log_inauthentic(object, message)
        logger.error("mAuth signature authentication failed for #{object.class}. Exception: #{message}")
      end

      def log_unable_to_authenticate(message)
        logger.error("Unable to authenticate with MAuth. Exception #{message}")
      end

      def log_mauth_not_present(object, message)
        logger.warn("mAuth signature not present on #{object.class}. Exception: #{message}")
      end

      def time_within_valid_range!(object, time_signed, now = Time.now)
        return if  (-ALLOWED_DRIFT_SECONDS..ALLOWED_DRIFT_SECONDS).cover?(now.to_i - time_signed)

        msg = "Time verification failed. #{time_signed} not within #{ALLOWED_DRIFT_SECONDS} of #{now}"
        log_mauth_not_present(object, msg)
        raise InauthenticError, msg
      end

      # V1 helpers
      def authenticate_v1!(object)
        time_valid_v1!(object)
        token_valid_v1!(object)
        signature_valid_v1!(object)
      end

      def authentication_present_v1(object)
        !object.x_mws_authentication.nil? || object.x_mws_authentication&.match?(/\S/)
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

      def authentication_present_v2(object)
        !object.mcc_authentication.nil? || object.mcc_authentication&.match?(/\S/)
      end

      def authentication_present_v2!(object)
        return if authentication_present_v2(object)

        msg = 'Authentication Failed. No mAuth signature present; MCC-Authentication header is blank.'
        log_mauth_not_present(object, msg)
        raise MauthNotPresent, msg
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
