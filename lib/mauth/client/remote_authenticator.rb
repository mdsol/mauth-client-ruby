# frozen_string_literal: true

# methods for remotely authenticating a request by sending it to the mauth service

module MAuth
  class Client
    module RemoteRequestAuthenticator
      private

      # takes an incoming request object (no support for responses currently), and errors if the
      # object is not authentic according to its signature
      def signature_valid_v1!(object)
        unless object.is_a?(MAuth::Request)
          raise ArgumentError,
            "Remote Authenticator can only authenticate requests; received #{object.inspect}"
        end

        authentication_ticket = {
          "verb" => object.attributes_for_signing[:verb],
          "app_uuid" => object.signature_app_uuid,
          "client_signature" => object.signature,
          "request_url" => object.attributes_for_signing[:request_url],
          "request_time" => object.x_mws_time,
          "b64encoded_body" => Base64.encode64(object.attributes_for_signing[:body] || "")
        }
        make_mauth_request(authentication_ticket)
      end

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
          b64encoded_body: Base64.encode64(object.attributes_for_signing[:body] || ""),
          query_string: object.attributes_for_signing[:query_string],
          token: object.signature_token
        }
        make_mauth_request(authentication_ticket)
      end

      def make_mauth_request(authentication_ticket)
        begin
          request_body = JSON.generate(authentication_ticket: authentication_ticket)
          response = mauth_connection.post("/mauth/#{mauth_api_version}/authentication_tickets.json", request_body)
        rescue ::Faraday::ConnectionFailed, ::Faraday::TimeoutError => e
          msg = "mAuth service did not respond; received #{e.class}: #{e.message}"
          logger.error("Unable to authenticate with MAuth. Exception #{msg}")
          raise UnableToAuthenticateError, msg
        end
        case response.status
        when 200..299
          nil
        when 412, 404
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
        @mauth_connection ||= begin
          require "faraday"

          ::Faraday.new(mauth_baseurl,
            faraday_options.merge(headers: { "Content-Type" => "application/json" })) do |builder|
            builder.use MAuth::Faraday::MAuthClientUserAgent
            builder.adapter ::Faraday.default_adapter
          end
        end
      end
    end
  end
end
