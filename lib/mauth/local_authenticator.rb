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
      class SecurityTokenCacher
        class ExpirableSecurityToken < Struct.new(:security_token, :create_time)
          CACHE_LIFE = 60
          def expired?
            create_time + CACHE_LIFE < Time.now
          end
        end
        def initialize(mauth_client)
          @mauth_client = mauth_client
          # TODO: should this be UnableToSignError?
          @mauth_client.assert_private_key(UnableToAuthenticateError.new("Cannot fetch public keys from mAuth service without a private key!"))
          @cache = {}
          require 'thread'
          @cache_write_lock = Mutex.new
        end

        def get(app_uuid)
          if !@cache[app_uuid] || @cache[app_uuid].expired?
            # url-encode the app_uuid to prevent trickery like escaping upward with ../../ in a malicious
            # app_uuid - probably not exploitable, but this is the right way to do it anyway.
            # use UNRESERVED instead of UNSAFE (the default) as UNSAFE doesn't include /
            url_encoded_app_uuid = URI.escape(app_uuid, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
            begin
              response = signed_mauth_connection.get("/mauth/#{@mauth_client.mauth_api_version}/security_tokens/#{url_encoded_app_uuid}.json")
            rescue ::Faraday::Error::ConnectionFailed, ::Faraday::Error::TimeoutError => e
              msg = "mAuth service did not respond; received #{e.class}: #{e.message}"
              @mauth_client.logger.error("Unable to authenticate with MAuth. Exception #{msg}")
              raise UnableToAuthenticateError, msg
            end
            if response.status == 200
              begin
                security_token = JSON.parse(response.body)
              rescue JSON::ParserError => e
                msg =  "mAuth service responded with unparseable json: #{response.body}\n#{e.class}: #{e.message}"
                @mauth_client.logger.error("Unable to authenticate with MAuth. Exception #{msg}")
                raise UnableToAuthenticateError, msg
              end
              @cache_write_lock.synchronize do
                @cache[app_uuid] = ExpirableSecurityToken.new(security_token, Time.now)
              end
            elsif response.status == 404
              # signing with a key mAuth doesn't know about is considered inauthentic
              raise InauthenticError, "mAuth service responded with 404 looking up public key for #{app_uuid}"
            else
              @mauth_client.send(:mauth_service_response_error, response)
            end
          end
          @cache[app_uuid].security_token
        end

        private

        def signed_mauth_connection
          require 'faraday'
          require 'mauth/faraday'
          @mauth_client.faraday_options[:ssl] = { ca_path: @mauth_client.ssl_certs_path } if @mauth_client.ssl_certs_path
          @signed_mauth_connection ||= ::Faraday.new(@mauth_client.mauth_baseurl, @mauth_client.faraday_options) do |builder|
            builder.use MAuth::Faraday::MAuthClientUserAgent
            builder.use MAuth::Faraday::RequestSigner, 'mauth_client' => @mauth_client
            builder.adapter ::Faraday.default_adapter
          end
        end
      end
    end
  end
end
