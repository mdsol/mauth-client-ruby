require File.dirname(__FILE__) + '/spec_helper'
require 'mauth/client'
require 'faraday'

describe MAuth::Client do
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
        assert_equal value, mc.send(config_key)
        # set with a symbol 
        mc = MAuth::Client.new(config_key.to_s => value)
        # check the accossor method 
        assert_equal value, mc.send(config_key)
      end
    end

    it 'logs to Rails.logger if it can' do
      Object.const_set('Rails', Object.new)
      def (::Rails).logger
        @logger ||= Logger.new(STDERR)
      end
      assert_equal ::Rails.logger, MAuth::Client.new.logger
      Object.send(:remove_const, 'Rails')
    end

    it 'builds a logger if Rails is defined, but Rails.logger is nil' do
      Object.const_set('Rails', Object.new)
      def (::Rails).logger
        nil
      end
      logger = mock('logger')
      ::Logger.stub(:new).with(anything).and_return(logger)
      assert_equal logger, MAuth::Client.new.logger
      Object.send(:remove_const, 'Rails')
    end

    it 'initializes with app_uuid' do
      uuid = "40e19273-6a43-41d1-ba71-71cbb1b69d35"
      [{:app_uuid => uuid}, {'app_uuid' => uuid}].each do |config|
        mc = MAuth::Client.new(config)
        assert_equal uuid, mc.client_app_uuid
      end
    end

    it 'initializes with private key' do
      key = OpenSSL::PKey::RSA.generate(2048)
      [{:private_key => key}, {'private_key' => key}, {:private_key => key.to_s}, {'private_key' => key.to_s}].each do |config|
        mc = MAuth::Client.new(config)
        # can't directly compare the OpenSSL::PKey::RSA instances 
        assert_equal key.class, mc.private_key.class
        assert_equal key.to_s, mc.private_key.to_s
      end
    end
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
  end

  describe '#signed' do
    before { @request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom') }
    it 'adds X-MWS-Time and X-MWS-Authentication headers when signing' do
      mc = MAuth::Client.new(:private_key => OpenSSL::PKey::RSA.generate(2048), :app_uuid => UUIDTools::UUID.random_create.to_s)
      signed_request = mc.signed(@request)
      assert signed_request.headers.keys.include?('X-MWS-Authentication')
      assert signed_request.headers.keys.include?('X-MWS-Time')
    end
    it "can't sign without a private key" do
      mc = MAuth::Client.new(:app_uuid => UUIDTools::UUID.random_create.to_s)
      assert_raises(MAuth::UnableToSignError) { mc.signed(@request) }
    end
    it "can't sign without an app uuid" do
      mc = MAuth::Client.new(:private_key => OpenSSL::PKey::RSA.generate(2048))
      assert_raises(MAuth::UnableToSignError) { mc.signed(@request) }
    end
  end
  describe '#signed_headers' do
    it 'returns a hash with X-MWS-Time and X-MWS-Authentication headers' do
      mc = MAuth::Client.new(:private_key => OpenSSL::PKey::RSA.generate(2048), :app_uuid => UUIDTools::UUID.random_create.to_s)
      signed_headers = mc.signed_headers(TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom'))
      assert signed_headers.keys.include?('X-MWS-Authentication')
      assert signed_headers.keys.include?('X-MWS-Time')
    end
  end

  describe 'authenticators' do
    before do
      @signing_key = OpenSSL::PKey::RSA.generate(2048)
      @app_uuid = 'signer'
      @signing_mc = MAuth::Client.new(:private_key => @signing_key, :app_uuid => @app_uuid)
    end

    shared_examples MAuth::Client::Authenticator do
      it "considers an authentically-signed request to be inauthentic when it's too old or too far in the future" do
        request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
        {-301 => false, -299 => true, 299 => true, 301 => false}.each do |time_offset, authentic|
          signed_request = @signing_mc.signed(request, :time => Time.now.to_i + time_offset)
          message = "expected request signed at #{time_offset} seconds to #{authentic ? "" : "not"} be authentic"
          if authentic
            assert @authenticating_mc.authentic?(signed_request), message
          else
            assert_raise_with_message(MAuth::InauthenticError, /Time verification failed for .*\. .* not within 300 of/, message) do
              @authenticating_mc.authenticate!(signed_request)
            end
          end
        end
      end
      it "considers an authentically-signed request to be inauthentic when it has no x-mws-time" do
        request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
        signed_request = @signing_mc.signed(request)
        signed_request.headers.delete('X-MWS-Time')
        assert_raise_with_message(MAuth::InauthenticError, /Time verification failed for .*\. No x-mws-time present\./) do
          @authenticating_mc.authenticate!(signed_request)
        end
      end
      it "considers a request with no X-MWS-Authentication to be inauthentic" do
        request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
        signed_request = @signing_mc.signed(request)
        signed_request.headers.delete('X-MWS-Authentication')
        assert_raise_with_message(MAuth::InauthenticError, "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank.") do
          @authenticating_mc.authenticate!(signed_request)
        end
      end
      it "considers a request with a bad MWS token to be inauthentic" do
        request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
        ['mws', 'm.w.s', 'm w s', 'NWS', ' MWS'].each do |bad_token|
          signed_request = @signing_mc.signed(request)
          signed_request.headers['X-MWS-Authentication'] = signed_request.headers['X-MWS-Authentication'].sub(/\AMWS/, bad_token)
          assert_raise_with_message(MAuth::InauthenticError, /Token verification failed for .*\. Expected "MWS"; token was .*/) do
            @authenticating_mc.authenticate!(signed_request)
          end
        end
      end
      [::Faraday::Error::ConnectionFailed, ::Faraday::Error::TimeoutError].each do |error_klass|
        it "raises UnableToAuthenticate if mauth is unreachable with #{error_klass.name}" do
          @test_faraday.stub(:get).and_raise(error_klass.new(''))
          @test_faraday.stub(:post).and_raise(error_klass.new(''))
          request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
          signed_request = @signing_mc.signed(request)
          assert_raises(MAuth::UnableToAuthenticateError) { @authenticating_mc.authentic?(signed_request) }
        end
      end
      it "raises UnableToAuthenticate if mauth errors" do
        @stubs.instance_eval{ @stack.clear } #HAX 
        @stubs.get("/mauth/v1/security_tokens/#{@app_uuid}.json") { [500, {}, []] } # for the local authenticator 
        @stubs.post('/mauth/v1/authentication_tickets.json') { [500, {}, []] } # for the remote authenticator 
        request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
        signed_request = @signing_mc.signed(request)
        assert_raises(MAuth::UnableToAuthenticateError) { @authenticating_mc.authentic?(signed_request) }
      end
    end

    describe MAuth::Client::LocalAuthenticator do
      describe '#authentic?' do
        before do
          @authenticating_mc = MAuth::Client.new(:mauth_baseurl => 'http://whatever', :mauth_api_version => 'v1', :private_key => OpenSSL::PKey::RSA.generate(2048), :app_uuid => 'authenticator')
          assert @authenticating_mc.is_a?(MAuth::Client::LocalAuthenticator)
          require 'faraday'
          stubs = @stubs = Faraday::Adapter::Test::Stubs.new
          @test_faraday = ::Faraday.new do |builder|
            builder.adapter(:test, stubs) do |stub|
              stub.get("/mauth/v1/security_tokens/#{@app_uuid}.json") { [200, {}, JSON.generate({'security_token' => {'public_key_str' => @signing_key.public_key.to_s}})] }
            end
          end
          ::Faraday.stub(:new).and_return(@test_faraday)
        end
        include_examples MAuth::Client::Authenticator
        it 'considers an authentically-signed request to be authentic' do
          request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
          signed_request = @signing_mc.signed(request)
          assert @authenticating_mc.authentic?(signed_request)
        end
        # Note:  We need this feature because some web servers (e.g. nginx) unescape 
        # URIs in PATH_INFO before sending them along to the served applications.  This added to the
        # fact that Euresource percent-encodes just about everything in the path except '/' leads to 
        # this somewhat odd test.
        it "considers a request to be authentic even if the request_url must be CGI::escape'ed (after being escaped in Euresource's own idiosyncratic way) before authenticity is achieved" do
          ['/v1/users/pjones+1@mdsol.com', "!	#	$	&	'	(	)	*	+	,	/	:	;	=	?	@	[	]"].each do |path|
            # imagine what are on the requester's side now...
            signed_path = CGI.escape(path).gsub!('%2F','/') # This is what Euresource does to the path on the requester's side before the signing of the outgoing request occurs.
            request = TestSignableRequest.new(:verb => 'GET', :request_url => signed_path)
            signed_request = @signing_mc.signed(request)
          
            # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
            decoded_signed_request = signed_request.clone
            decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
            assert @authenticating_mc.authentic?(decoded_signed_request)
          end
        end
        # And the above example inspires a slightly less unusual case, in which the path is fully percent-encoded 
        it "considers a request to be authentic even if the request_url must be CGI::escape'ed before authenticity is achieved" do
          ['/v1/users/pjones+1@mdsol.com', "!	#	$	&	'	(	)	*	+	,	/	:	;	=	?	@	[	]"].each do |path|
            # imagine what are on the requester's side now...
            signed_path = CGI.escape(path)
            request = TestSignableRequest.new(:verb => 'GET', :request_url => signed_path)
            signed_request = @signing_mc.signed(request)
          
            # now that we've signed the request, imagine it goes to nginx where it gets percent-decoded
            decoded_signed_request = signed_request.clone
            decoded_signed_request.attributes_for_signing[:request_url] = CGI.unescape(decoded_signed_request.attributes_for_signing[:request_url])
            assert @authenticating_mc.authentic?(decoded_signed_request)
          end
        end
        it 'considers a request signed by an app uuid unknown to mauth to be inauthentic' do
          request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
          signing_mc = MAuth::Client.new(:private_key => @signing_key, :app_uuid => 'nope')
          @stubs.get("/mauth/v1/security_tokens/nope.json") { [404, {}, []] }
          signed_request = signing_mc.signed(request)
          assert !@authenticating_mc.authentic?(signed_request)
        end
        it "considers a request with a bad signature to be inauthentic" do
          request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
          signed_request = @signing_mc.signed(request)
          signed_request.headers['X-MWS-Authentication'] = "MWS #{@app_uuid}:wat"
          assert !@authenticating_mc.authentic?(signed_request)
        end
        it "considers a request that has been tampered with to be inauthentic" do
          request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
          signed_request = @signing_mc.signed(request)
          signed_request.attributes_for_signing[:verb] = 'DELETE'
          assert !@authenticating_mc.authentic?(signed_request)
        end
      end
    end

    describe MAuth::Client::RemoteRequestAuthenticator do
      describe '#authentic?' do
        before do
          @authenticating_mc = MAuth::Client.new(:mauth_baseurl => 'http://whatever', :mauth_api_version => 'v1')
          assert @authenticating_mc.is_a?(MAuth::Client::RemoteRequestAuthenticator)
          require 'faraday'
          stubs = @stubs = Faraday::Adapter::Test::Stubs.new
          @test_faraday = ::Faraday.new do |builder|
            builder.adapter(:test, stubs)
          end
          @stubs.post('/mauth/v1/authentication_tickets.json') { [204, {}, []] }
          ::Faraday.stub(:new).and_return(@test_faraday)
        end
        include_examples MAuth::Client::Authenticator
        it 'considers a request to be authentic if mauth reports it so' do
          request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
          signed_request = @signing_mc.signed(request)
          assert @authenticating_mc.authentic?(signed_request)
        end
        it 'considers a request to be inauthentic if mauth reports it so' do
          @stubs.instance_eval{ @stack.clear } #HAX 
          @stubs.post('/mauth/v1/authentication_tickets.json') { [412, {}, []] }
          request = TestSignableRequest.new(:verb => 'PUT', :request_url => '/', :body => 'himom')
          signed_request = @signing_mc.signed(request)
          assert !@authenticating_mc.authentic?(signed_request)
        end
      end
    end
  end
end
