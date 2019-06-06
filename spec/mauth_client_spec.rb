require 'spec_helper'
require 'faraday'
require 'mauth/client'
require 'securerandom'

# edge cases for specs
# -> unencoded equals in value
# -> empty string
# -> extended utf8 chars
# -> special chars
# -> ks w no vs
# -> ks w multiple vs and starting with extended chars sort by codepoint
# -> sort by codepoint of key then value

describe MAuth::Client do
  let(:app_uuid) { SecureRandom.uuid }
  let(:request) { TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom') }
  let(:sign_requests_with_only_v2) { false }
  let(:authenticate_with_only_v2) { false }
  let(:v1_signed_req) { client.signed(request, v1_only_override: true) }
  let(:v2_signed_req) { client.signed(request, v2_only_override: true) }
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:client) do
    MAuth::Client.new(
      private_key: signing_key,
      app_uuid: app_uuid,
      sign_requests_with_only_v2: sign_requests_with_only_v2,
      authenticate_with_only_v2: authenticate_with_only_v2
    )
  end

  describe '#initialize' do
    it 'initializes without config' do
      mc = MAuth::Client.new
    end

    require 'logger'
    config_pieces = {
      :logger => ::Logger.new(STDERR),
      :mauth_baseurl => 'https://mauth.imedidata.net',
      :mauth_api_version => 'v1',
    }
    config_pieces.each do |config_key, value|
      it "initializes with #{config_key}" do
        # set with a string
        mc = MAuth::Client.new(config_key.to_s => value)
        # check the accessor method
        expect(value).to eq(mc.send(config_key))
        # set with a symbol
        mc = MAuth::Client.new(config_key.to_s => value)
        # check the accossor method
        expect(value).to eq(mc.send(config_key))
      end
    end

    it 'logs to Rails.logger if it can' do
      Object.const_set('Rails', Object.new)
      def (::Rails).logger
        @logger ||= Logger.new(STDERR)
      end
      expect(::Rails.logger).to eq(MAuth::Client.new.logger)
      Object.send(:remove_const, 'Rails')
    end

    it 'builds a logger if Rails is defined, but Rails.logger is nil' do
      Object.const_set('Rails', Object.new)
      def (::Rails).logger
        nil
      end
      logger = double('logger')
      allow(::Logger).to receive(:new).with(anything).and_return(logger)
      expect(logger).to eq(MAuth::Client.new.logger)
      Object.send(:remove_const, 'Rails')
    end

    it 'initializes with app_uuid' do
      uuid = "40e19273-6a43-41d1-ba71-71cbb1b69d35"
      [{:app_uuid => uuid}, {'app_uuid' => uuid}].each do |config|
        mc = MAuth::Client.new(config)
        expect(uuid).to eq(mc.client_app_uuid)
      end
    end

    it 'initializes with ssl_cert_path' do
      ssl_certs_path = 'ssl/certs/path'
      [{:ssl_certs_path => ssl_certs_path}, {'ssl_certs_path' => ssl_certs_path}].each do |config|
        mc = MAuth::Client.new(config)
        expect(ssl_certs_path).to eq(mc.ssl_certs_path)
      end
    end

    it 'initializes with private key' do
      key = OpenSSL::PKey::RSA.generate(2048)
      [{:private_key => key}, {'private_key' => key}, {:private_key => key.to_s}, {'private_key' => key.to_s}].each do |config|
        mc = MAuth::Client.new(config)
        # can't directly compare the OpenSSL::PKey::RSA instances
        expect(key.class).to eq(mc.private_key.class)
        expect(key.to_s).to eq(mc.private_key.to_s)
      end
    end

    it 'initializes with authenticate_with_only_v2'
    it 'initializes with sign_requests_with_only_v2'
  end

  require 'mauth/request_and_response'
  class TestSignableRequest < MAuth::Request
    include MAuth::Signed
    attr_accessor :headers

    def merge_headers(headers)
      self.class.new(@attributes_for_signing).tap{|r| r.headers = (@headers || {}).merge(headers) }
    end

    def x_mws_time
      headers['X-MWS-Time']
    end

    def x_mws_authentication
      headers['X-MWS-Authentication']
    end

    def mcc_authentication
      headers['MCC-Authentication']
    end

    def mcc_time
      headers['MCC-Time']
    end
  end

  describe '#signed' do
    it 'adds only X-MWS-Time and X-MWS-Authentication headers when signing with v1 override' do
      expect(v1_signed_req.headers.keys).to include('X-MWS-Authentication')
      expect(v1_signed_req.headers.keys).to include('X-MWS-Time')
      expect(v1_signed_req.headers.keys).not_to include('MCC-Authentication')
      expect(v1_signed_req.headers.keys).not_to include('MCC-Time')
    end

    it 'adds only MCC-Time and MCC-Authentication headers when signing with v2 override' do
      expect(v2_signed_req.headers.keys).to include('MCC-Authentication')
      expect(v2_signed_req.headers.keys).to include('MCC-Time')
      expect(v2_signed_req.headers.keys).not_to include('X-MWS-Authentication')
      expect(v2_signed_req.headers.keys).not_to include('X-MWS-Time')
    end

    context 'when the sign_requests_with_only_v2 flag is true' do
      let(:sign_requests_with_only_v2) { true }

      it 'adds only MCC-Time and MCC-Authentication headers when signing' do
        signed_request = client.signed(request)
        expect(signed_request.headers.keys).to include('MCC-Authentication')
        expect(signed_request.headers.keys).to include('MCC-Time')
        expect(signed_request.headers.keys).not_to include('X-MWS-Authentication')
        expect(signed_request.headers.keys).not_to include('X-MWS-Time')
      end
    end

    it 'by default adds X-MWS-Time, X-MWS-Authentication, MCC-Time, MCC-Authentication headers when signing' do
      signed_request = client.signed(request)
      expect(signed_request.headers.keys).to include('X-MWS-Authentication')
      expect(signed_request.headers.keys).to include('X-MWS-Time')
      expect(signed_request.headers.keys).to include('MCC-Authentication')
      expect(signed_request.headers.keys).to include('MCC-Time')
    end

    it "can't sign without a private key" do
      mc = MAuth::Client.new(:app_uuid => app_uuid)
      expect { mc.signed(request) }.to raise_error(MAuth::UnableToSignError)
    end

    it "can't sign without an app uuid" do
      mc = MAuth::Client.new(:private_key => OpenSSL::PKey::RSA.generate(2048))
      expect { mc.signed(request) }.to raise_error(MAuth::UnableToSignError)
    end
  end

  describe '#signed_headers' do
    it 'returns only X-MWS-Time and X-MWS-Authentication headers when called with v1 override' do
      signed_headers = client.signed_headers(request, v1_only_override: true)
      expect(signed_headers.keys).to include('X-MWS-Authentication')
      expect(signed_headers.keys).to include('X-MWS-Time')
      expect(signed_headers.keys).not_to include('MCC-Authentication')
      expect(signed_headers.keys).not_to include('MCC-Time')
    end

    it 'returns only MCC-Time and MCC-Authentication headers when called with v2 override' do
      signed_headers = client.signed_headers(request, v2_only_override: true)
      expect(signed_headers.keys).to include('MCC-Authentication')
      expect(signed_headers.keys).to include('MCC-Time')
      expect(signed_headers.keys).not_to include('X-MWS-Authentication')
      expect(signed_headers.keys).not_to include('X-MWS-Time')
    end

    context 'when the sign_requests_with_only_v2 flag is true' do
      let(:sign_requests_with_only_v2) { true }

      it 'returns only MCC-Time and MCC-Authentication headers when signing' do
        signed_headers = client.signed_headers(request)
        expect(signed_headers.keys).to include('MCC-Authentication')
        expect(signed_headers.keys).to include('MCC-Time')
        expect(signed_headers.keys).not_to include('X-MWS-Authentication')
        expect(signed_headers.keys).not_to include('X-MWS-Time')
      end
    end

    it 'by default returns X-MWS-Time, X-MWS-Authentication, MCC-Time, MCC-Authentication headers' do
      signed_headers = client.signed_headers(request)
      expect(signed_headers.keys).to include('X-MWS-Authentication')
      expect(signed_headers.keys).to include('X-MWS-Time')
      expect(signed_headers.keys).to include('MCC-Authentication')
      expect(signed_headers.keys).to include('MCC-Time')
    end
  end

  describe 'authenticators' do
    let(:app_uuid) { 'signer' }

    shared_examples MAuth::Client::Authenticator do
      context 'when v2 and v1 headers are present on the object to authenticate' do
        it 'authenticates with v2'

        it "considers an authentically-signed request to be inauthentic when it's too old or too far in the future" do
          {-301 => false, -299 => true, 299 => true, 301 => false}.each do |time_offset, authentic|
            signed_request = client.signed(request, :time => Time.now.to_i + time_offset)
            message = "expected request signed at #{time_offset} seconds to #{authentic ? "" : "not"} be authentic"
            if authentic
              expect(authenticating_mc.authentic?(signed_request)).to be_truthy, message
            else
              expect { authenticating_mc.authenticate!(signed_request) }.to(
                  raise_error(MAuth::InauthenticError, /Time verification failed\. .* not within 300 of/),
                  message
                )
            end
          end
        end

        it "considers an authentically-signed request to be inauthentic when it has no MCC-time" do
          signed_request = client.signed(request)
          signed_request.headers.delete('MCC-Time')
          expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
              MAuth::InauthenticError,
              /Time verification failed\. No MCC-Time present\./
            )
        end

        it "considers a request with a bad V2 token to be inauthentic" do
          ['mws2', 'm.w.s', 'm w s', 'NWSv2', ' MWS'].each do |bad_token|
            signed_request = client.signed(request)
            signed_request.headers['MCC-Authentication'] = signed_request.headers['MCC-Authentication'].sub(/\AMWSV2/, bad_token)
              expect { authenticating_mc.authenticate!(signed_request)}.to raise_error(
                MAuth::InauthenticError, /Token verification failed\. Expected MWSV2; token was .*/)
          end
        end

        describe 'logging requester and requestee' do
          before do
            allow(authenticating_mc).to receive(:client_app_uuid).and_return('authenticator')
          end

          it 'logs the mauth app uuid of the requester and requestee when they both have such uuids' do
            signed_request = client.signed(request, :time => Time.now.to_i)
            expect(authenticating_mc.logger).to receive(:info).with("Mauth-client attempting to authenticate request from app with mauth app uuid signer to app with mauth app uuid authenticator using version MWSV2.")
            authenticating_mc.authentic?(signed_request)
          end

          it 'says when the mauth app uuid is not provided in the request' do
            signed_request = client.signed(request, :time => Time.now.to_i)
            allow(signed_request).to receive(:signature_app_uuid).and_return(nil)
            expect(authenticating_mc.logger).to receive(:info).with("Mauth-client attempting to authenticate request from app with mauth app uuid [none provided] to app with mauth app uuid authenticator using version MWSV2.")
            authenticating_mc.authentic?(signed_request) rescue nil
          end
        end
      end

      context 'when only v1 headers are present on the object to authenticate' do

        it 'authenticates with v1'

        it "considers an authentically-signed request to be inauthentic when it's too old or too far in the future" do
          {-301 => false, -299 => true, 299 => true, 301 => false}.each do |time_offset, authentic|
            signed_request = client.signed(request, :time => Time.now.to_i + time_offset, v1_only_override: true)
            message = "expected request signed at #{time_offset} seconds to #{authentic ? "" : "not"} be authentic"
            if authentic
              expect(authenticating_mc.authentic?(signed_request)).to be_truthy, message
            else
              expect { authenticating_mc.authenticate!(signed_request) }.to(
                  raise_error(MAuth::InauthenticError, /Time verification failed\. .* not within 300 of/),
                  message
                )
            end
          end
        end

        it "considers an authentically-signed request to be inauthentic when it has no x-mws-time" do
          v1_signed_req.headers.delete('X-MWS-Time')
          expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
              MAuth::InauthenticError,
              /Time verification failed\. No x-mws-time present\./
            )
        end

        it "considers a request with no X-MWS-Authentication to be inauthentic" do
          v1_signed_req.headers.delete('X-MWS-Authentication')
          expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
              MAuth::MauthNotPresent,
              'Authentication Failed. No mAuth signature present;  X-MWS-Authentication header is blank, MCC-Authentication header is blank.'
            )
        end

        it "considers a request with a bad MWS token to be inauthentic" do
          ['mws', 'm.w.s', 'm w s', 'NWS', ' MWS'].each do |bad_token|
              v1_signed_req.headers['X-MWS-Authentication'] = v1_signed_req.headers['X-MWS-Authentication'].sub(/\AMWS/, bad_token)
              expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
                MAuth::InauthenticError, /Token verification failed\. Expected MWS; token was .*/)
          end
        end

        [::Faraday::Error::ConnectionFailed, ::Faraday::Error::TimeoutError].each do |error_klass|
          it "raises UnableToAuthenticate if mauth is unreachable with #{error_klass.name}" do
            allow(test_faraday).to receive(:get).and_raise(error_klass.new(''))
            allow(test_faraday).to receive(:post).and_raise(error_klass.new(''))
              expect { authenticating_mc.authentic?(v1_signed_req) }.to raise_error(MAuth::UnableToAuthenticateError)
          end
        end

        it "raises UnableToAuthenticate if mauth errors" do
          stubs.instance_eval{ @stack.clear } #HAX
          stubs.get("/mauth/v1/security_tokens/#{app_uuid}.json") { [500, {}, []] } # for the local authenticator
          stubs.post('/mauth/v1/authentication_tickets.json') { [500, {}, []] } # for the remote authenticator
          expect {  authenticating_mc.authentic?(v1_signed_req) }.to raise_error(MAuth::UnableToAuthenticateError)
        end

        describe 'logging requester and requestee' do
          before do
            allow(authenticating_mc).to receive(:client_app_uuid).and_return('authenticator')
          end

          it 'logs the mauth app uuid of the requester and requestee when they both have such uuids' do
            v1_signed_req = client.signed(request, :time => Time.now.to_i)
            expect(authenticating_mc.logger).to receive(:info).with("Mauth-client attempting to authenticate request from app with mauth app uuid signer to app with mauth app uuid authenticator using version MWSV2.")
            authenticating_mc.authentic?(v1_signed_req)
          end

          it 'says when the mauth app uuid is not provided in the request' do
            v1_signed_req = client.signed(request, :time => Time.now.to_i)
            allow(v1_signed_req).to receive(:signature_app_uuid).and_return(nil)
            expect(authenticating_mc.logger).to receive(:info).with("Mauth-client attempting to authenticate request from app with mauth app uuid [none provided] to app with mauth app uuid authenticator using version MWSV2.")
            authenticating_mc.authentic?(v1_signed_req) rescue nil
          end

        end
      end

      context 'when authenticate_with_only_v2 flag is true' do
        let(:authenticate_with_only_v2) { true }

        it 'authenticates with v2' do

        end

        it 'raises MissingV2Error if v2 headers are not present and v1 headers are present' do
          expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
            MAuth::MissingV2Error
          )
        end

        it "considers a request with no v2 or v1 headers to be inauthentic" do
          signed_request = client.signed(request)
          signed_request.headers.delete('MCC-Authentication')
          signed_request.headers.delete('X-MWS-Authentication')
          expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
            MAuth::MauthNotPresent,
            "Authentication Failed. No mAuth signature present; MCC-Authentication header is blank."
          )
        end
      end
    end

    describe MAuth::Client::LocalAuthenticator do
      describe '#authentic?' do
        let(:authenticate_with_only_v2) { false }
        let(:authenticating_mc) do
          MAuth::Client.new(
            mauth_baseurl: 'http://whatever',
            mauth_api_version: 'v1',
            private_key: OpenSSL::PKey::RSA.generate(2048),
            app_uuid: 'authenticator',
            authenticate_with_only_v2: authenticate_with_only_v2
          )
        end
        let(:test_faraday) do
          ::Faraday.new do |builder|
            builder.adapter(:test, stubs) do |stub|
              stub.get("/mauth/v1/security_tokens/#{app_uuid}.json") { [200, {}, JSON.generate({'security_token' => {'public_key_str' => signing_key.public_key.to_s}})] }
            end
          end
        end
        let(:stubs) { Faraday::Adapter::Test::Stubs.new }

        before do
          expect(authenticating_mc).to be_kind_of(MAuth::Client::LocalAuthenticator)
          allow(::Faraday).to receive(:new).and_return(test_faraday)
        end

        include_examples MAuth::Client::Authenticator

        it 'considers an authentically-signed request to be authentic' do
          signed_request = client.signed(request)
          expect(authenticating_mc.authentic?(signed_request)).to be_truthy
        end

        # Note:  We need this feature because some web servers (e.g. nginx) unescape
        # URIs in PATH_INFO before sending them along to the served applications.  This added to the
        # fact that Euresource percent-encodes just about everything in the path except '/' leads to
        # this somewhat odd test.
        it "considers a request to be authentic even if the request_url must be CGI::escape'ed (after being escaped in Euresource's own idiosyncratic way) before authenticity is achieved" do
          ['/v1/users/pjones+1@mdsol.com', "! # $ & ' ( ) * + , / : ; = ? @ [ ]"].each do |path|
            # imagine what are on the requester's side now...
            signed_path = CGI.escape(path).gsub!(/%2F|%23/, "%2F" => "/", "%23" => "#") # This is what Euresource does to the path on the requester's side before the signing of the outgoing request occurs.
            req_w_path = TestSignableRequest.new(:verb => 'GET', :request_url => signed_path)
            signed_request = client.signed(req_w_path)

            # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
            decoded_signed_request = signed_request.clone
            decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
            expect(authenticating_mc.authentic?(decoded_signed_request)).to be_truthy
          end
        end

        # And the above example inspires a slightly less unusual case, in which the path is fully percent-encoded
        it "considers a request to be authentic even if the request_url must be CGI::escape'ed before authenticity is achieved" do
          ['/v1/users/pjones+1@mdsol.com', "! # $ & ' ( ) * + , / : ; = ? @ [ ]"].each do |path|
            # imagine what are on the requester's side now...
            signed_path = CGI.escape(path)
            req_w_path = TestSignableRequest.new(:verb => 'GET', :request_url => signed_path)
            signed_request = client.signed(req_w_path)

            # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
            decoded_signed_request = signed_request.clone
            decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
            expect(authenticating_mc.authentic?(decoded_signed_request)).to be_truthy
          end
        end

        it 'considers a request signed by an app uuid unknown to mauth to be inauthentic' do
          client = MAuth::Client.new(:private_key => signing_key, :app_uuid => 'nope')
          stubs.get("/mauth/v1/security_tokens/nope.json") { [404, {}, []] }
          signed_request = client.signed(request)
          expect(authenticating_mc.authentic?(signed_request)).to be_falsey
        end

        it "considers a request with a bad signature to be inauthentic" do
          signed_request = client.signed(request)
          signed_request.headers['MCC-Authentication'] = "MWS #{app_uuid}:wat"
          expect(authenticating_mc.authentic?(signed_request)).to be_falsey
        end

        it "considers a request that has been tampered with to be inauthentic" do
          signed_request = client.signed(request)
          signed_request.attributes_for_signing[:verb] = 'DELETE'
          expect(authenticating_mc.authentic?(signed_request)).to be_falsey
        end

        context 'v2' do
          it 'considers an authentically signed request with a query string to be authentic'
          it 'considers a request to be authentic '

          # Note:  We need this feature because some web servers (e.g. nginx) unescape
          # URIs in PATH_INFO before sending them along to the served applications.  This added to the
          # fact that Euresource percent-encodes just about everything in the path except '/' leads to
          # this somewhat odd test.
          xit "considers a request with a query string to be authentic even if the request_url must be CGI::escape'ed (after being escaped in Euresource's own idiosyncratic way) before authenticity is achieved" do
            ['/v1/users/pjones+1@mdsol.com', "! # $ & ' ( ) * + , / : ; = ? @ [ ]"].each do |path|
              # imagine what are on the requester's side now...
              signed_path = CGI.escape(path).gsub!(/%2F|%23/, "%2F" => "/", "%23" => "#") # This is what Euresource does to the path on the requester's side before the signing of the outgoing request occurs.
              req_w_path = TestSignableRequest.new(:verb => 'GET', :request_url => signed_path)
              signed_request = client.signed(req_w_path)

              # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
              decoded_signed_request = signed_request.clone
              decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
              expect(authenticating_mc.authentic?(decoded_signed_request)).to be_truthy
            end
          end

          # And the above example inspires a slightly less unusual case, in which the path is fully percent-encoded
          xit "considers a request with a query to be authentic even if the request_url must be CGI::escape'ed before authenticity is achieved" do
            ['/v1/users/pjones+1@mdsol.com', "! # $ & ' ( ) * + , / : ; = ? @ [ ]"].each do |path|
              # imagine what are on the requester's side now...
              signed_path = CGI.escape(path)
              req_w_path = TestSignableRequest.new(:verb => 'GET', :request_url => signed_path)
              signed_request = client.signed(req_w_path)

              # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
              decoded_signed_request = signed_request.clone
              decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
              expect(authenticating_mc.authentic?(decoded_signed_request)).to be_truthy
            end
          end
        end
      end

      describe MAuth::Client::LocalAuthenticator::SecurityTokenCacher do
        describe '#signed_mauth_connection' do
          it 'properly sets the timeouts on the faraday connection' do
            config = {
              'private_key' => OpenSSL::PKey::RSA.generate(2048),
              'faraday_options' => {'timeout' => '23', 'open_timeout' => '18'},
              'mauth_baseurl' => 'https://mauth.imedidata.net'
            }
            mc = MAuth::Client.new(config)
            connection = MAuth::Client::LocalAuthenticator::SecurityTokenCacher.new(mc).send(:signed_mauth_connection)
            expect(connection.options[:timeout]).to eq('23')
            expect(connection.options[:open_timeout]).to eq('18')
          end
        end
      end
    end

    describe MAuth::Client::RemoteRequestAuthenticator do
      describe '#authentic?' do
        let(:stubs) { Faraday::Adapter::Test::Stubs.new }
        let(:authenticating_mc) do
          MAuth::Client.new(
            mauth_baseurl: 'http://whatever',
            mauth_api_version: 'v1',
            authenticate_with_only_v2: authenticate_with_only_v2
          )
        end
        let(:test_faraday) do
          ::Faraday.new do |builder|
            builder.adapter(:test, stubs)
          end
        end

        before do
          expect(authenticating_mc).to be_kind_of(MAuth::Client::RemoteRequestAuthenticator)
          stubs.post('/mauth/v1/authentication_tickets.json') { [204, {}, []] }
          allow(::Faraday).to receive(:new).and_return(test_faraday)
        end

        include_examples MAuth::Client::Authenticator

        it 'considers a request to be authentic if mauth reports it so' do
          signed_request = client.signed(request)
          expect(authenticating_mc.authentic?(signed_request)).to be_truthy
        end

        it 'considers a request to be inauthentic if mauth reports it so' do
          stubs.instance_eval{ @stack.clear } #HAX
          stubs.post('/mauth/v1/authentication_tickets.json') { [412, {}, []] }
          signed_request = client.signed(request)
          expect(authenticating_mc.authentic?(signed_request)).to be_falsey
        end
      end
    end
  end
end
