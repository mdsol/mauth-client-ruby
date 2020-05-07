require 'spec_helper'
require 'faraday'
require 'mauth/client'
require_relative '../support/shared_contexts/client.rb'
require_relative '../support/shared_examples/authenticator_base.rb'


describe MAuth::Client::LocalAuthenticator do
  include_context 'client'

  describe '#authentic?' do
    let(:v2_only_authenticate) { false }
    let(:authenticating_mc) do
      MAuth::Client.new(
        mauth_baseurl: 'http://whatever',
        mauth_api_version: 'v1',
        private_key: OpenSSL::PKey::RSA.generate(2048),
        app_uuid: 'authenticator',
        v2_only_authenticate: v2_only_authenticate,
        disable_fallback_to_v1_on_v2_failure: disable_fallback_to_v1_on_v2_failure
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

    include_examples MAuth::Client::AuthenticatorBase


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
      let(:binary_request) do
        TestSignableRequest.new(
          verb: 'PUT',
          request_url: '/',
          body: binary_file_body,
          query_string: 'key=value&coolkey=coolvalue'
        )
      end
      let(:binary_filepath) { 'spec/fixtures/blank.jpeg' }
      let(:binary_file_body) { File.binread(binary_filepath) }
      let(:v2_only_authenticate) { true }

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
          signed_qs = CGI.escape(qs).gsub(/%3D|%26/, '%3D' => '=', '%26' => '&')
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

      it 'considers a signed request with a request body of binary data to be authentic' do
        signed_request = client.signed(binary_request)
        expect(authenticating_mc.authentic?(signed_request)).to be true
      end

      it 'considers a signed request with a request body of binary data that was read in from disk to be authentic' do
        # the signing mauth client should be able to stream large request bodies
        # from the disk straight into the hashing function like so:
        streamed_hash_digest = Digest::SHA512.file(binary_filepath).hexdigest
        # used the digest from streaming in the file when signing the request
        signed_request = client.signed(binary_request, body_digest: streamed_hash_digest)
        expect(authenticating_mc.authentic?(signed_request)).to be true
      end

      it 'considers a request with the wrong body_digest to be inauthentic' do
        wrong_hash_digest = Digest::SHA512.hexdigest('abc')
        signed_request = client.signed(binary_request, body_digest: wrong_hash_digest)
        expect(authenticating_mc.authentic?(signed_request)).to be false
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
