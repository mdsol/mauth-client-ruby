# frozen_string_literal: true

require "faraday-http-cache"
require "mauth/faraday"

module MAuth
  class Client
    module LocalAuthenticator
      class SecurityTokenCacher
        def initialize(mauth_client)
          @mauth_client = mauth_client
          # TODO: should this be UnableToSignError?
          @mauth_client.assert_private_key(
            UnableToAuthenticateError.new("Cannot fetch public keys from mAuth service without a private key!")
          )
        end

        def get(app_uuid)
          # url-encode the app_uuid to prevent trickery like escaping upward with ../../ in a malicious
          # app_uuid - probably not exploitable, but this is the right way to do it anyway.
          url_encoded_app_uuid = CGI.escape(app_uuid)
          path = "/mauth/#{@mauth_client.mauth_api_version}/security_tokens/#{url_encoded_app_uuid}.json"
          response = signed_mauth_connection.get(path)

          case response.status
          when 200
            security_token_from(response.body)
          when 404
            # signing with a key mAuth doesn't know about is considered inauthentic
            raise InauthenticError, "mAuth service responded with 404 looking up public key for #{app_uuid}"
          else
            @mauth_client.send(:mauth_service_response_error, response)
          end
        rescue ::Faraday::ConnectionFailed, ::Faraday::TimeoutError => e
          msg = "mAuth service did not respond; received #{e.class}: #{e.message}"
          @mauth_client.logger.error("Unable to authenticate with MAuth. Exception #{msg}")
          raise UnableToAuthenticateError, msg
        end

        private

        def security_token_from(response_body)
          JSON.parse response_body
        rescue JSON::ParserError => e
          msg = "mAuth service responded with unparseable json: #{response_body}\n#{e.class}: #{e.message}"
          @mauth_client.logger.error("Unable to authenticate with MAuth. Exception #{msg}")
          raise UnableToAuthenticateError, msg
        end

        def signed_mauth_connection
          @signed_mauth_connection ||= begin
            if @mauth_client.ssl_certs_path
              @mauth_client.faraday_options[:ssl] = { ca_path: @mauth_client.ssl_certs_path }
            end

            ::Faraday.new(@mauth_client.mauth_baseurl, @mauth_client.faraday_options) do |builder|
              builder.use MAuth::Faraday::MAuthClientUserAgent
              builder.use MAuth::Faraday::RequestSigner, "mauth_client" => @mauth_client
              builder.use :http_cache, logger: MAuth::Client.new.logger, shared_cache: false
              builder.adapter ::Faraday.default_adapter
            end
          end
        end
      end
    end
  end
end
