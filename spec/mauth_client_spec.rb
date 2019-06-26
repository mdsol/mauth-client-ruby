require 'spec_helper'
require 'faraday'
require 'mauth/client'
require 'securerandom'

describe MAuth::Client do
  let(:app_uuid) { SecureRandom.uuid }
  let(:request) { TestSignableRequest.new(verb: 'PUT', request_url: '/', body: 'himom') }
  let(:v2_only_sign_requests) { false }
  let(:v2_only_authenticate) { false }
  let(:v1_signed_req) { client.signed_v1(request) }
  let(:v2_signed_req) { client.signed_v2(request) }
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:client) do
    MAuth::Client.new(
      private_key: signing_key,
      app_uuid: app_uuid,
      v2_only_sign_requests: v2_only_sign_requests,
      v2_only_authenticate: v2_only_authenticate
    )
  end

  describe '#initialize' do
    it 'initializes without config' do
      mc = MAuth::Client.new
    end

    require 'logger'
    config_pieces = {
      logger: ::Logger.new(STDERR),
      mauth_baseurl: 'https://mauth.imedidata.net',
      mauth_api_version: 'v1',
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
      [{ app_uuid: uuid }, { 'app_uuid' => uuid }].each do |config|
        mc = MAuth::Client.new(config)
        expect(uuid).to eq(mc.client_app_uuid)
      end
    end

    it 'initializes with ssl_cert_path' do
      ssl_certs_path = 'ssl/certs/path'
      [{ ssl_certs_path: ssl_certs_path }, { 'ssl_certs_path' => ssl_certs_path }].each do |config|
        mc = MAuth::Client.new(config)
        expect(ssl_certs_path).to eq(mc.ssl_certs_path)
      end
    end

    it 'initializes with private key' do
      key = OpenSSL::PKey::RSA.generate(2048)
      [{ private_key: key }, { 'private_key' => key }, { private_key: key.to_s }, { 'private_key' => key.to_s }].each do |config|
        mc = MAuth::Client.new(config)
        # can't directly compare the OpenSSL::PKey::RSA instances
        expect(key.class).to eq(mc.private_key.class)
        expect(key.to_s).to eq(mc.private_key.to_s)
      end
    end

    it 'correctly initializes with v2_only_authenticate as true with boolean true or string "true"' do
      [true, 'true', 'TRUE'].each do |val|
        [{ v2_only_authenticate: val }, { 'v2_only_authenticate' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v2_only_authenticate?).to eq(true)
        end
      end
    end

    it 'correctly initializes with v2_only_authenticate as false with any other values' do
      ['tru', false, 'false', 1, 0, nil, ''].each do |val|
        [{ v2_only_authenticate: val }, { 'v2_only_authenticate' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v2_only_authenticate?).to eq(false)
        end
      end
    end

    it 'correctly initializes with v2_only_sign_requests as true with boolean true or string "true"' do
      [true, 'true', 'TRUE'].each do |val|
        [{ v2_only_sign_requests: val }, { 'v2_only_sign_requests' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v2_only_sign_requests?).to eq(true)
        end
      end
    end

    it 'correctly initializes with v2_only_sign_requests as false with any other values' do
      ['tru', false, 'false', 1, 0, nil].each do |val|
        [{ v2_only_sign_requests: val }, { 'v2_only_sign_requests' => val }].each do |config|
          mc = MAuth::Client.new(config)
          expect(mc.v2_only_sign_requests?).to eq(false)
        end
      end
    end
  end

  require 'mauth/request_and_response'
  class TestSignableRequest < MAuth::Request
    include MAuth::Signed
    attr_accessor :headers

    def merge_headers(headers)
      self.class.new(@attributes_for_signing).tap{ |r| r.headers = (@headers || {}).merge(headers) }
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
    context 'when the v2_only_sign_requests flag is true' do
      let(:v2_only_sign_requests) { true }

      it 'adds only MCC-Time and MCC-Authentication headers when signing' do
        signed_request = client.signed(request)
        expect(signed_request.headers.keys).to include('MCC-Authentication', 'MCC-Time')
        expect(signed_request.headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
      end
    end

    it 'by default adds X-MWS-Time, X-MWS-Authentication, MCC-Time, MCC-Authentication headers when signing' do
      signed_request = client.signed(request)
      expect(signed_request.headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time','MCC-Authentication', 'MCC-Time')
    end

    it "can't sign without a private key" do
      mc = MAuth::Client.new(app_uuid: app_uuid)
      expect { mc.signed(request) }.to raise_error(MAuth::UnableToSignError)
    end

    it "can't sign without an app uuid" do
      mc = MAuth::Client.new(private_key: OpenSSL::PKey::RSA.generate(2048))
      expect { mc.signed(request) }.to raise_error(MAuth::UnableToSignError)
    end
  end

  describe '#signed_v1' do
    it 'adds only X-MWS-Time and X-MWS-Authentication headers' do
      expect(v1_signed_req.headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time')
      expect(v1_signed_req.headers.keys).not_to include('MCC-Authentication', 'MCC-Time')
    end
  end

  describe '#signed_v2' do
    it 'adds only MCC-Time and MCC-Authentication headers' do
      expect(v2_signed_req.headers.keys).to include('MCC-Authentication', 'MCC-Time')
      expect(v2_signed_req.headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
    end
  end

  describe '#signed_headers' do
    context 'when the v2_only_sign_requests flag is true' do
      let(:v2_only_sign_requests) { true }

      it 'returns only MCC-Time and MCC-Authentication headers when signing' do
        signed_headers = client.signed_headers(request)
        expect(signed_headers.keys).to include('MCC-Authentication', 'MCC-Time')
        expect(signed_headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
      end
    end

    it 'by default returns X-MWS-Time, X-MWS-Authentication, MCC-Time, MCC-Authentication headers' do
      signed_headers = client.signed_headers(request)
      expect(signed_headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time', 'MCC-Authentication', 'MCC-Time')
    end
  end

  describe '#signed_headers_v1' do
    it 'returns only X-MWS-Time and X-MWS-Authentication headers' do
      signed_headers = client.signed_headers_v1(request)
      expect(signed_headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time')
      expect(signed_headers.keys).not_to include('MCC-Authentication', 'MCC-Time')
    end
  end

  describe '#signed_headers_v2' do
    it 'returns only MCC-Time and MCC-Authentication headers' do
      signed_headers = client.signed_headers_v2(request)
      expect(signed_headers.keys).to include('MCC-Authentication', 'MCC-Time')
      expect(signed_headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
    end
  end

  describe 'authenticators' do
    let(:app_uuid) { 'signer' }

    shared_examples MAuth::Client::Authenticator do
      context 'when v2 and v1 headers are present on the object to authenticate' do
        it 'authenticates with v2' do
          signed_request = client.signed(request)
          expect(authenticating_mc).to receive(:signature_valid_v2!).with(signed_request)
          expect(authenticating_mc).not_to receive(:signature_valid_v1!)
          authenticating_mc.authentic?(signed_request)
        end

        it "considers an authentically-signed request to be inauthentic when it's too old or too far in the future" do
          [-301, 301].each do |time_offset|
            signed_request = client.signed(request, time: Time.now.to_i + time_offset)
            message = "expected request signed at #{time_offset} seconds to be inauthentic"
            expect { authenticating_mc.authenticate!(signed_request) }.to(
              raise_error(MAuth::InauthenticError, /Time verification failed\. .* not within 300 of/),
              message
            )
          end
        end

        it "considers an authentically-signed request to be authentic when it's within the allowed time range" do
          [-300, -299, 299, 300].each do |time_offset|
            signed_request = client.signed(request, time: Time.now.to_i + time_offset)
            message = "expected request signed at #{time_offset} seconds to be authentic"
            expect(authenticating_mc.authentic?(signed_request)).to eq(true), message
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
              expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
                MAuth::InauthenticError, /Token verification failed\. Expected MWSV2; token was .*/)
          end
        end

        describe 'logging requester and requestee' do
          before do
            allow(authenticating_mc).to receive(:client_app_uuid).and_return('authenticator')
          end

          it 'logs the mauth app uuid of the requester and requestee when they both have such uuids' do
            signed_request = client.signed(request, time: Time.now.to_i)
            expect(authenticating_mc.logger).to receive(:info).with(
              'Mauth-client attempting to authenticate request from app with mauth ' \
              'app uuid signer to app with mauth app uuid authenticator using version MWSV2.'
            )
            authenticating_mc.authentic?(signed_request)
          end

          it 'logs when the mauth app uuid is not provided in the request' do
            signed_request = client.signed(request, time: Time.now.to_i)
            allow(signed_request).to receive(:signature_app_uuid).and_return(nil)
            expect(authenticating_mc.logger).to receive(:info).with(
              'Mauth-client attempting to authenticate request from app with mauth app uuid ' \
              '[none provided] to app with mauth app uuid authenticator using version MWSV2.'
            )
            authenticating_mc.authentic?(signed_request) rescue nil
          end
        end
      end

      context 'when only v1 headers are present on the object to authenticate' do

        it 'authenticates with v1' do
          expect(authenticating_mc).to receive(:signature_valid_v1!).with(v1_signed_req)
          expect(authenticating_mc).not_to receive(:signature_valid_v2!)
          authenticating_mc.authentic?(v1_signed_req)
        end

        it "considers an authentically-signed request to be inauthentic when it's too old or too far in the future" do
          [-301, 301].each do |time_offset|
            signed_request = client.signed_v1(request, time: Time.now.to_i + time_offset)
            message = "expected request signed at #{time_offset} seconds to be inauthentic"
            expect { authenticating_mc.authenticate!(signed_request) }.to(
              raise_error(MAuth::InauthenticError, /Time verification failed\. .* not within 300 of/),
              message
            )
          end
        end

        it "considers an authentically-signed request to be authentic when it's within the allowed time range" do
          [-300, -299, 299, 300].each do |time_offset|
            signed_request = client.signed_v1(request, time: Time.now.to_i + time_offset)
            message = "expected request signed at #{time_offset} seconds to be authentic"
            expect(authenticating_mc.authentic?(signed_request)).to eq(true), message
          end
        end

        it "considers an authentically-signed request to be inauthentic when it has no x-mws-time" do
          v1_signed_req.headers.delete('X-MWS-Time')
          expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
              MAuth::InauthenticError,
              /Time verification failed\. No x-mws-time present\./
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
            allow(test_faraday).to receive(:get).and_raise(error_klass.new('')) # for the local authenticator
            allow(test_faraday).to receive(:post).and_raise(error_klass.new('')) # for the remote authenticator
            expect { authenticating_mc.authentic?(v1_signed_req) }.to raise_error(MAuth::UnableToAuthenticateError)
          end
        end

        it "raises UnableToAuthenticate if mauth errors" do
          stubs.instance_eval{ @stack.clear } #HAX
          stubs.get("/mauth/v1/security_tokens/#{app_uuid}.json") { [500, {}, []] } # for the local authenticator
          stubs.post('/mauth/v1/authentication_tickets.json') { [500, {}, []] } # for the remote authenticator
          expect { authenticating_mc.authentic?(v1_signed_req) }.to raise_error(MAuth::UnableToAuthenticateError)
        end

        describe 'logging requester and requestee' do
          before do
            allow(authenticating_mc).to receive(:client_app_uuid).and_return('authenticator')
          end

          it 'logs the mauth app uuid of the requester and requestee when they both have such uuids' do
            expect(authenticating_mc.logger).to receive(:info).with(
              'Mauth-client attempting to authenticate request from app with mauth app' \
              ' uuid signer to app with mauth app uuid authenticator using version MWS.'
            )
            authenticating_mc.authentic?(v1_signed_req)
          end

          it 'logs when the mauth app uuid is not provided in the request' do
            allow(v1_signed_req).to receive(:signature_app_uuid).and_return(nil)
            expect(authenticating_mc.logger).to receive(:info).with(
              'Mauth-client attempting to authenticate request from app with mauth app' \
              ' uuid [none provided] to app with mauth app uuid authenticator using version MWS.'
            )
            authenticating_mc.authentic?(v1_signed_req) rescue nil
          end

        end
      end

      context 'when no headers are present on the object to authenticate' do
        it "considers a request without v1 and v2 headers to be inauthentic" do
          signed_request = client.signed(request)
          signed_request.headers.delete('X-MWS-Authentication')
          signed_request.headers.delete('MCC-Authentication')
          expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
            MAuth::MauthNotPresent,
            'Authentication Failed. No mAuth signature present; X-MWS-Authentication ' \
            'header is blank, MCC-Authentication header is blank.'
          )
        end

        it "considers a request with empty v1 and v2 headers to be inauthentic" do
          signed_request = client.signed(request)
          signed_request.headers['X-MWS-Authentication'] = ''
          signed_request.headers['MCC-Authentication'] = ''
          expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
            MAuth::MauthNotPresent,
            'Authentication Failed. No mAuth signature present; X-MWS-Authentication' \
            ' header is blank, MCC-Authentication header is blank.'
          )
        end
      end

      context 'when v2_only_authenticate flag is true' do
        let(:v2_only_authenticate) { true }

        it 'authenticates with v2' do
          signed_request = client.signed(request)
          expect(authenticating_mc).to receive(:signature_valid_v2!).with(signed_request)
          expect(authenticating_mc).not_to receive(:signature_valid_v1!)
          authenticating_mc.authentic?(signed_request)
        end

        it 'raises MissingV2Error if v2 headers are not present and v1 headers are present' do
          expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
            MAuth::MissingV2Error
          )
        end

        it 'considers a request without v2 or v1 headers to be inauthentic' do
          signed_request = client.signed(request)
          signed_request.headers.delete('MCC-Authentication')
          signed_request.headers.delete('X-MWS-Authentication')
          expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
            MAuth::MauthNotPresent,
            'Authentication Failed. No mAuth signature present; MCC-Authentication header is blank.'
          )
        end

        it 'considers a request with an empty v2 header to be inauthentic' do
          signed_request = client.signed(request)
          signed_request.headers['MCC-Authentication'] = ''
          signed_request.headers.delete('X-MWS-Authentication')
          expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
            MAuth::MauthNotPresent,
            'Authentication Failed. No mAuth signature present; MCC-Authentication header is blank.'
          )
        end
      end
    end

    describe MAuth::Client::LocalAuthenticator do
      describe '#authentic?' do
        let(:v2_only_authenticate) { false }
        let(:authenticating_mc) do
          MAuth::Client.new(
            mauth_baseurl: 'http://whatever',
            mauth_api_version: 'v1',
            private_key: OpenSSL::PKey::RSA.generate(2048),
            app_uuid: 'authenticator',
            v2_only_authenticate: v2_only_authenticate
          )
        end
        let(:test_faraday) do
          ::Faraday.new do |builder|
            builder.adapter(:test, stubs) do |stub|
              stub.get("/mauth/v1/security_tokens/#{app_uuid}.json") { [200, {}, JSON.generate({ 'security_token' => { 'public_key_str' => signing_key.public_key.to_s } })] }
            end
          end
        end
        let(:stubs) { Faraday::Adapter::Test::Stubs.new }

        before do
          expect(authenticating_mc).to be_kind_of(MAuth::Client::LocalAuthenticator)
          allow(::Faraday).to receive(:new).and_return(test_faraday)
        end

        include_examples MAuth::Client::Authenticator


        context 'when authenticating with v1' do
          it 'considers an authentically-signed request to be authentic' do
            expect(authenticating_mc.authentic?(v1_signed_req)).to be true
          end

          # Note:  We need this feature because some web servers (e.g. nginx) unescape
          # URIs in PATH_INFO before sending them along to the served applications.  This added to the
          # fact that Euresource percent-encodes just about everything in the path except '/' leads to
          # this somewhat odd test.
          it "considers a request to be authentic even if the request_url must be CGI::escape'ed (after being escaped in Euresource's own idiosyncratic way) before authenticity is achieved" do
            ['/v1/users/pjones+1@mdsol.com', "! # $ & ' ( ) * + , / : ; = ? @ [ ]"].each do |path|
              # imagine what are on the requester's side now...
              signed_path = CGI.escape(path).gsub!(/%2F|%23/, "%2F" => "/", "%23" => "#") # This is what Euresource does to the path on the requester's side before the signing of the outgoing request occurs.
              req_w_path = TestSignableRequest.new(verb: 'GET', request_url: signed_path)
              signed_request = client.signed_v1(req_w_path)

              # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
              decoded_signed_request = signed_request.clone
              decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
              expect(authenticating_mc.authentic?(decoded_signed_request)).to be true
            end
          end

          # And the above example inspires a slightly less unusual case, in which the path is fully percent-encoded
          it "considers a request to be authentic even if the request_url must be CGI::escape'ed before authenticity is achieved" do
            ['/v1/users/pjones+1@mdsol.com', "! # $ & ' ( ) * + , / : ; = ? @ [ ]"].each do |path|
              # imagine what are on the requester's side now...
              signed_path = CGI.escape(path)
              req_w_path = TestSignableRequest.new(verb: 'GET', request_url: signed_path)
              signed_request = client.signed_v1(req_w_path)

              # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
              decoded_signed_request = signed_request.clone
              decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
              expect(authenticating_mc.authentic?(decoded_signed_request)).to be true
            end
          end

          it 'considers a request signed by an app uuid unknown to mauth to be inauthentic' do
            bad_client = MAuth::Client.new(private_key: signing_key, app_uuid: 'nope')
            signed_request = bad_client.signed_v1(request)
            stubs.get("/mauth/v1/security_tokens/nope.json") { [404, {}, []] }
            expect(authenticating_mc.authentic?(signed_request)).to be_falsey
          end

          it 'considers a request with a bad signature to be inauthentic' do
            v1_signed_req.headers['X-MWS-Authentication'] = "MWS #{app_uuid}:wat"
            expect(authenticating_mc.authentic?(v1_signed_req)).to be_falsey
          end

          it 'considers a request that has been tampered with to be inauthentic' do
            v1_signed_req.attributes_for_signing[:verb] = 'DELETE'
            expect(authenticating_mc.authentic?(v1_signed_req)).to be_falsey
          end
        end


        context 'when authenticating with v2' do
          let(:qs_request) do
            TestSignableRequest.new(
              verb: 'PUT',
              request_url: '/',
              body: 'himom',
              query_string: 'key=value&coolkey=coolvalue'
            )
          end

          it 'considers an authentically-signed request to be authentic' do
            signed_request = client.signed(request)
            expect(authenticating_mc.authentic?(signed_request)).to be true
          end

          it 'considers an authentically signed request with query parameters to be authentic' do
            signed_request = client.signed(qs_request)
            expect(authenticating_mc.authentic?(signed_request)).to be true
          end

          # Note:  We need this feature because some web servers (e.g. nginx) unescape
          # URIs in PATH_INFO before sending them along to the served applications.  This added to the
          # fact that Euresource percent-encodes just about everything in the path except '/' leads to
          # this somewhat odd test.
          it "considers a request with query parameters to be authentic even if the request_url must be CGI::escape'ed (after being escaped in Euresource's own idiosyncratic way) before authenticity is achieved" do
            [
              ['/v1/users/pjones+1@mdsol.com',  'nice=cool&good=great'],
              ["! # $ & ' ( ) * + , / : ; = ? @ [ ]", "param=\\'df+P=%5C"]
            ].each do |path, qs|
              # imagine what are on the requester's side now...
              signed_path = CGI.escape(path).gsub(/%2F|%23/, "%2F" => "/", "%23" => "#") # This is what Euresource does to the path on the requester's side before the signing of the outgoing request occurs.
              signed_qs = CGI.escape(qs).gsub(/%2F|%23/, "%2F" => "/", "%23" => "#")
              req_w_path = TestSignableRequest.new(verb: 'GET', request_url: signed_path, query_string: signed_qs)
              signed_request = client.signed(req_w_path)

              # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
              decoded_signed_request = signed_request.clone
              decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
              decoded_signed_request.attributes_for_signing[:query_string] = CGI.unescape(decoded_signed_request.attributes_for_signing[:query_string])
              expect(authenticating_mc.authentic?(decoded_signed_request)).to be true
            end
          end

          # And the above example inspires a slightly less unusual case, in which the path is fully percent-encoded
          it "considers a request with query parameters to be authentic even if the request_url must be CGI::escape'ed before authenticity is achieved" do
            [
              ['/v1/users/pjones+1@mdsol.com',  'nice=cool&good=great'],
              ["! # $ & ' ( ) * + , / : ; = ? @ [ ]", "param=\\'df+P=%5C"]
            ].each do |path, qs|
              # imagine what are on the requester's side now...
              signed_path = CGI.escape(path)
              signed_qs = CGI.escape(qs)
              req_w_path = TestSignableRequest.new(verb: 'GET', request_url: signed_path, query_string: signed_qs)
              signed_request = client.signed(req_w_path)

              # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
              decoded_signed_request = signed_request.clone
              decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
              decoded_signed_request.attributes_for_signing[:query_string] = CGI.unescape(decoded_signed_request.attributes_for_signing[:query_string])
              expect(authenticating_mc.authentic?(decoded_signed_request)).to be true
            end
          end

          it 'considers a request signed by an app uuid unknown to mauth to be inauthentic' do
            bad_client = MAuth::Client.new(private_key: signing_key, app_uuid: 'nope')
            signed_request = bad_client.signed(request)
            stubs.get("/mauth/v1/security_tokens/nope.json") { [404, {}, []] }
            expect(authenticating_mc.authentic?(signed_request)).to be_falsey
          end

          it 'considers a request with a bad signature to be inauthentic' do
            signed_request = client.signed(request)
            signed_request.headers['MCC-Authentication'] = "MWS #{app_uuid}:wat"
            expect(authenticating_mc.authentic?(signed_request)).to be_falsey
          end

          it 'considers a request that has been tampered with to be inauthentic' do
            signed_request = client.signed(request)
            signed_request.attributes_for_signing[:verb] = 'DELETE'
            expect(authenticating_mc.authentic?(signed_request)).to be_falsey
          end

          it 'considers a request with many repeated query params authentic' do
            pairs = (1..100).reduce([]) do |acc, el|
              acc.push(['param1', el], ['param2', el])
            end.shuffle

            request = TestSignableRequest.new(
              verb: 'PUT',
              request_url: '/',
              body: 'himom',
              query_string: pairs.map { |pair| pair.join('=') }.join('&')
            )
            signed_request = client.signed(request)
            expect(authenticating_mc.authentic?(signed_request)).to be true
          end

          it 'considers a signed request with multi-byte UTF-8 characters in the query string to be authentic' do
            request = TestSignableRequest.new(
              verb: 'PUT',
              request_url: '/',
              body: 'himom',
              query_string: 'prm=val&prm=𝖛𝗮ḷ&パラメータ=値&매개 변수=값&參數=值'
            )
            signed_request = client.signed(request)
            expect(authenticating_mc.authentic?(signed_request)).to be true
          end

          it 'considers a signed request with repeated query param keys with multi-byte UTF-8 character values to be authentic' do
            qs = 'prm=パ&prm=개'

            request = TestSignableRequest.new(
              verb: 'PUT',
              request_url: '/',
              body: 'himom',
              query_string: qs
            )
            signed_request = client.signed(request)
            expect(authenticating_mc.authentic?(signed_request)).to be true
          end

        end
      end

      describe MAuth::Client::LocalAuthenticator::SecurityTokenCacher do
        describe '#signed_mauth_connection' do
          it 'properly sets the timeouts on the faraday connection' do
            config = {
              'private_key' => OpenSSL::PKey::RSA.generate(2048),
              'faraday_options' => { 'timeout' => '23', 'open_timeout' => '18' },
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
            v2_only_authenticate: v2_only_authenticate
          )
        end
        let(:test_faraday) do
          ::Faraday.new do |builder|
            builder.adapter(:test, stubs)
          end
        end
        let(:query_string) { 'key=value&coolkey=coolvalue' }
        let(:qs_request) do
          TestSignableRequest.new(
            verb: 'PUT',
            request_url: '/',
            body: 'himom',
            query_string: query_string
          )
        end

        before do
          expect(authenticating_mc).to be_kind_of(MAuth::Client::RemoteRequestAuthenticator)
          stubs.post('/mauth/v1/authentication_tickets.json') { [204, {}, []] }
          allow(::Faraday).to receive(:new).and_return(test_faraday)
        end

        include_examples MAuth::Client::Authenticator

        it 'considers a request to be authentic if mauth reports it so' do
          signed_request = client.signed(request)
          expect(authenticating_mc.authentic?(signed_request)).to be true
        end

        it 'considers a request to be inauthentic if mauth reports it so' do
          stubs.instance_eval{ @stack.clear } #HAX
          stubs.post('/mauth/v1/authentication_tickets.json') { [412, {}, []] }
          signed_request = client.signed(request)
          expect(authenticating_mc.authentic?(signed_request)).to be_falsey
        end

        context 'when authenticating with v2' do
          it 'includes the query string and token in the request' do
            expect(test_faraday).to receive(:post).with(
              '/mauth/v1/authentication_tickets.json',
              'authentication_ticket' => hash_including(query_string: query_string, token: 'MWSV2')
            ).and_return(double('resp', status: 200))

            signed_request = client.signed(qs_request)
            authenticating_mc.authentic?(signed_request)
          end
        end
      end
    end
  end
end
