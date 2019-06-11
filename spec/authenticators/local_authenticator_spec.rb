require 'spec_helper'
require 'mauth/client'
require 'mauth/authenticators/local_authenticator'
require_relative '../support/shared_examples/authenticators.rb'
require_relative '../support/shared_contexts/client_context'

describe MAuth::Client::LocalAuthenticator do
  include_context 'client'
  
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
        expect(authenticating_mc.authentic?(v1_signed_req)).to be_truthy
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
          signed_request = client.signed(req_w_path, v1_only_override: true)

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
          req_w_path = TestSignableRequest.new(verb: 'GET', request_url: signed_path)
          signed_request = client.signed(req_w_path, v1_only_override: true)

          # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
          decoded_signed_request = signed_request.clone
          decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
          expect(authenticating_mc.authentic?(decoded_signed_request)).to be_truthy
        end
      end

      it 'considers a request signed by an app uuid unknown to mauth to be inauthentic' do
        bad_client = MAuth::Client.new(private_key: signing_key, app_uuid: 'nope')
        signed_request = bad_client.signed(request, v1_only_override: true)
        stubs.get("/mauth/v1/security_tokens/nope.json") { [404, {}, []] }
        expect(authenticating_mc.authentic?(signed_request)).to be_falsey
      end

      it "considers a request with a bad signature to be inauthentic" do
        v1_signed_req.headers['X-MWS-Authentication'] = "MWS #{app_uuid}:wat"
        expect(authenticating_mc.authentic?(v1_signed_req)).to be_falsey
      end

      it "considers a request that has been tampered with to be inauthentic" do
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
        expect(authenticating_mc.authentic?(signed_request)).to be_truthy
      end

      it 'considers an authentically signed request with with query parameters to be authentic' do
        signed_request = client.signed(qs_request)
        expect(authenticating_mc.authentic?(signed_request)).to be_truthy
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
          expect(authenticating_mc.authentic?(decoded_signed_request)).to be_truthy
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
          expect(authenticating_mc.authentic?(decoded_signed_request)).to be_truthy
        end
      end

      it 'considers a request signed by an app uuid unknown to mauth to be inauthentic' do
        bad_client = MAuth::Client.new(private_key: signing_key, app_uuid: 'nope')
        signed_request = bad_client.signed(request)
        stubs.get("/mauth/v1/security_tokens/nope.json") { [404, {}, []] }
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

      it 'considers a request with many repeated query params authentic' do
        pairs = (1..100).reduce([]) { |acc, el|  acc << [1, el] } +
          (1..100).reduce([]) { |acc, el|  acc << [2, el] }
        pairs.shuffle!

        request = TestSignableRequest.new(
          verb: 'PUT',
          request_url: '/',
          body: 'himom',
          query_string: pairs.map { |pair| pair.join('=') }.join('&')
        )
        signed_request = client.signed(request)
        expect(authenticating_mc.authentic?(signed_request)).to be_truthy
      end
    end
  end
end
