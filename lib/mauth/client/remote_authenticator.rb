# methods for remotely authenticating a request by sending it to the mauth service

module Mauth
  class Client
    module RemoteRequestAuthenticator
      private

      # takes an incoming request object (no support for responses currently), and errors if the
      # object is not authentic according to its signature
      def signature_valid_v1!(object)
        raise ArgumentError, "Remote Authenticator can only authenticate requests; received #{object.inspect}" unless object.is_a?(Mauth::Request)
        authentication_ticket = {
          'verb' => object.attributes_for_signing[:verb],
          'app_uuid' => object.signature_app_uuid,
          'client_signature' => object.signature,
          'request_url' => object.attributes_for_signing[:request_url],
          'request_time' => object.x_mws_time,
          'b64encoded_body' => Base64.encode64(object.attributes_for_signing[:body] || '')
        }
        make_mauth_request(authentication_ticket)
      end

      def signature_valid_v2!(object)
        unless object.is_a?(Mauth::Request)
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

      def make_mauth_request(authentication_ticket)
        begin
          response = mauth_connection.post("/mauth/#{mauth_api_version}/authentication_tickets.json", 'authentication_ticket' => authentication_ticket)
        rescue ::Faraday::ConnectionFailed, ::Faraday::TimeoutError => e
          msg = "mAuth service did not respond; received #{e.class}: #{e.message}"
          logger.error("Unable to authenticate with Mauth. Exception #{msg}")
          raise UnableToAuthenticateError, msg
        end
        if (200..299).cover?(response.status)
          nil
        elsif response.status == 412 || response.status == 404
          # the mAuth service responds with 412 when the given request is not authentically signed.
          # older versions of the mAuth service respond with 404 when the given app_uuid
          # does not exist, which is also considered to not be authentically signed. newer
          # versions of the service respond 412 in all cases, so the 404 check may be removed
          # when the old version of the mAuth service is out of service.
          raise InauthenticError, "The mAuth service responded with #{response.status}: #{response.body}"
        else
          mauth_service_response_error(response)
        end
      end

      def mauth_connection
        require 'faraday'
        require 'faraday_middleware'
        @mauth_connection ||= ::Faraday.new(mauth_baseurl, faraday_options) do |builder|
          builder.use Mauth::Faraday::MauthClientUserAgent
          builder.use FaradayMiddleware::EncodeJson
          builder.adapter ::Faraday.default_adapter
        end
      end
    end
  end
end
