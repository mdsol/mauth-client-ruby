require File.dirname(__FILE__) + '/spec_helper'

describe "Medidata::MAuthMiddleware" do

  before(:each) do
    @app = mock
    @app.stub(:call)
    config = {
      :mauth_baseurl => "http://localhost",
      :app_uuid => "app_uuid",
      :private_key => "secret",
      :version => "v1"
    }
    @mauthIncomingMiddleware = Medidata::MAuthMiddleware.new(@app, config)
    @secret_from_mauth = {"security_token" => {"private_key" => "shhh2", "app_uuid" => "6ff4257e-9c16-11e0-b048-0026bbfffe5f"}}.to_json
    @parsed_secret_from_mauth = {"6ff4257e-9c16-11e0-b048-0026bbfffe5f"=>{:private_key => "shhh2"}}
  end

  describe "#initialize" do
    it "raises exception if no config given" do
      lambda { Medidata::MAuthMiddleware.new(@app, nil) }.should raise_error Medidata::MAuthMiddleware::MissingBaseURL
    end

    it "raises exception if no mauth baseurl given in config" do
      lambda { Medidata::MAuthMiddleware.new(@app, {}) }.should raise_error Medidata::MAuthMiddleware::MissingBaseURL
    end

    it "raises an exception if config doesn't include :version" do
      config = {
        :mauth_baseurl => "http://localhost",
        :app_uuid => "app_uuid",
        :private_key => "secret"
      }
      lambda { Medidata::MAuthMiddleware.new(@app, config) }.should raise_error ArgumentError
    end
  end

  describe "#according_to" do
    context "remote mAuth is having problems" do
      before(:each) do
        @response = mock(Net::HTTPResponse)
      end

      after(:each) do
        @mauthIncomingMiddleware.should_receive(:mauth_server_error)
        @mauthIncomingMiddleware.send(:according_to, @response, 'dummy_app')
      end

      it "calls mauth_server_error when response was 500" do
        @response.stub_chain(:code, :to_i).and_return(500)
      end

      it "calls mauth_server_error when response was nil" do
        @response.stub(:nil?).and_return(true)
      end
    end

    context "remote mAuth responds with specific code" do
      before(:each) do
        @response = mock(Net::HTTPResponse)
      end

      it "receives a 200 response" do
        @response.stub_chain(:code, :to_i).and_return(200)
        @response.stub(:body).and_return('a body')
        @mauthIncomingMiddleware.send(:according_to, @response, 'dummy_app').should == 'a body'
      end

      it "receives a 404 response" do
        @response.stub_chain(:code, :to_i).and_return(404)
        @mauthIncomingMiddleware.send(:according_to, @response, 'dummy_app').should be_nil
      end

      it "receives an unexpected response code" do
        r_code = rand(199)+201
        app_uuid = 'dummy_app'
        @response.stub(:body).and_return("a body")
        @response.stub_chain(:code, :to_i).and_return(r_code)
        @mauthIncomingMiddleware.should_receive(:log).with("Attempt to refresh cache with secret from mAuth responded with #{r_code} #{@response.body} for #{app_uuid}")
        @mauthIncomingMiddleware.send(:according_to, @response, app_uuid).should be_nil
      end
    end

  end

  describe "#token_expired?" do
    context "with a token that was never set in cache" do
      it "returns true" do
        token = nil
        @mauthIncomingMiddleware.send(:token_expired?, token).should be
      end
    end

    context "with a token that was set more than a minute ago" do
      it "return true" do
        token = Hash.new
        token[:last_refresh] = Time.now
        Timecop.travel(Time.now + 61)
        @mauthIncomingMiddleware.send(:token_expired?, token).should be
        Timecop.return
      end
    end
  end

  describe "#should_authenticate?" do
    context "no whitelist" do
      it "returns true if no url_whitelist is defined" do
        @mauthIncomingMiddleware.send(:should_authenticate?, @env).should == true
      end
    end

    context "whitelist defined" do
      before(:each) do
        @base_config = {
          :mauth_baseurl => "http://localhost",
          :app_uuid => "app_uuid",
          :private_key => "secret",
          :version => "v1"
        }

        @base_env = {
          'HTTP_AUTHORIZATION' => "MWS app_uuid:digest",
          'REQUEST_METHOD' => 'GET',
          'REQUEST_URI' => 'example.com',
          'HTTP_X_MWS_TIME' => 123
        }
      end

      it "returns true if path info matches regex in whitelist" do
        config = @base_config.merge(:path_whitelist => [/^\/v2\/api/, /^\/api\/v2/])
        env = @base_env.merge('PATH_INFO' => '/api/v2/studies.json')

        mauthIncomingMiddleware2 = Medidata::MAuthMiddleware.new(@app, config)
        mauthIncomingMiddleware2.send(:should_authenticate?, env).should == true
      end

      it "returns false if path info does not match any regex in whitelist" do
        config = @base_config.merge(:path_whitelist => [/^\/v2\/api/, /^\/api\/v2/])
        env = @base_env.merge('PATH_INFO' => '/api/v1/studies.json')

        mauthIncomingMiddleware2 = Medidata::MAuthMiddleware.new(@app, config)
        mauthIncomingMiddleware2.send(:should_authenticate?, env).should == false
      end

      it "returns false if path info matches regex in whitelist but path info also matches exception" do
        config = @base_config.merge(:path_whitelist => [/^\/v2\/api/, /^\/api\/v2/], :whitelist_exceptions => [/^\/v2\/api\/request_tokens\.json/, /^\/api\/v2\/request_tokens\.json/])
        env = @base_env.merge('PATH_INFO' => '/api/v2/request_tokens.json')

        mauthIncomingMiddleware2 = Medidata::MAuthMiddleware.new(@app, config)
        mauthIncomingMiddleware2.send(:should_authenticate?, env).should == false
      end

      it "returns true if path info matches regex in whitelist and path info does not match any exception" do
        config = @base_config.merge(:path_whitelist => [/^\/v2\/api/, /^\/api\/v2/], :whitelist_exceptions => [/^\/v2\/api\/request_tokens\.json/, /^\/api\/v2\/request_tokens\.json/])
        env = @base_env.merge('PATH_INFO' => '/api/v2/sites.json')

        mauthIncomingMiddleware2 = Medidata::MAuthMiddleware.new(@app, config)
        mauthIncomingMiddleware2.send(:should_authenticate?, env).should == true
      end

    end
  end

  describe "#synch_cache" do
    context "deleting or adding a app_uuid" do
      before(:each) do
        @cached_secrets = {}
        @new_token = nil
        class << @mauthIncomingMiddleware
          def cached
            @cached_secrets
          end
        end
      end

      after(:each) do
        @mauthIncomingMiddleware.send(:synch_cache, @new_token, 'dummy_app')
      end

      it "deletes the app_uuid from the cached_secrets" do
        @cached_secrets = {'dummy_app' => 'dummy_value'}
        @mauthIncomingMiddleware.cached.should be_empty
      end

      it "adds the key-value pair to the @cached_secrets" do
        @new_token = {'dummy_app' => {:private_key => '123'} }
        @mauthIncomingMiddleware.cached.has_key?('dummy_app')
      end
    end

    [:private_key, :last_refresh].each do |key|
      it "adds a #{key} to the @cached_secrets" do
        class << @mauthIncomingMiddleware
          def cached
            @cached_secrets
          end
        end
        @new_token = {'dummy_app' => {:private_key => '123'} }
        @mauthIncomingMiddleware.send(:synch_cache, @new_token, 'dummy_app')
        @mauthIncomingMiddleware.cached['dummy_app'].should have_key(key)
      end
    end

  end


  describe "#call" do
    before(:each) do
      @env = {'HTTP_AUTHORIZATION' => "MWS app_uuid:digest", 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => 'example.com', 'HTTP_X_MWS_TIME' => 123}
    end

    context "when authenticating" do
      before(:each) do
        @mauthIncomingMiddleware.stub(:should_authenticate?).and_return(true)
      end

      it "calls the app if authentication succeeded" do
        @mauthIncomingMiddleware.stub(:authenticated?).and_return(true)
        @app.should_receive(:call)
        @mauthIncomingMiddleware.call(@env)
      end

      it "returns 401 (Unauthorized) if authentication failed" do
        @mauthIncomingMiddleware.stub(:authenticated?).and_return(false)
        @mauthIncomingMiddleware.call(@env).should == [401, {"Content-Type"=>"text/plain"}, ["Unauthorized"]]
      end
    end

    context "doesn't authenticate" do
      before(:each) do
        @mauthIncomingMiddleware.stub(:should_authenticate?).and_return(false)
      end

      it "calls the app" do
        @app.should_receive(:call)
        @mauthIncomingMiddleware.call(@env)
      end
    end
  end

  describe "#authenticated?" do
    before(:each) do
      @env = {'HTTP_AUTHORIZATION' => "MWS app_uuid:digest", 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => 'example.com', 'HTTP_X_MWS_TIME' => 123}
    end

    context "malformed header" do
      it "returns false if mws_token is not 'MWS'" do
        @env['HTTP_AUTHORIZATION'] = "MMM app_uuid:digest"
        @mauthIncomingMiddleware.send(:authenticated?, @env).should == false
      end

      it "returns false if app_uuid is not present" do
        @env['HTTP_AUTHORIZATION'] = "MWS"
        @mauthIncomingMiddleware.send(:authenticated?, @env).should == false
      end

      it "returns false if digest is not present" do
        @env['HTTP_AUTHORIZATION'] = "MWS"
        @mauthIncomingMiddleware.send(:authenticated?, @env).should == false
      end

    end

    it "authenticates locally if configured to do so" do
      @mauthIncomingMiddleware.stub(:can_authenticate_locally?).and_return(true)
      @mauthIncomingMiddleware.should_receive(:authenticate_locally)
      @mauthIncomingMiddleware.send(:authenticated?, @env)
    end

    it "authenticates remotely if configured to do so" do
      @mauthIncomingMiddleware.stub(:can_authenticate_locally?).and_return(false)
      @mauthIncomingMiddleware.should_receive(:authenticate_remotely)
      @mauthIncomingMiddleware.send(:authenticated?, @env)
    end
  end

  describe "#authenticate_locally" do
    before(:each) do
      @digest = "6327c1af329ba52478ad9ade1276d9b5b45962fb"
      @params = {
        :app_uuid    => "originator_app_uuid",
        :digest      => @digest,
        :verb        => "GET",
        :request_url => "/studies",
        :time        => 123
      }
      @mauthIncomingMiddleware.stub(:secret_for_app).and_return("secret")
    end

    after(:each) do
      @mauthIncomingMiddleware.send(:authenticate_locally, @digest, @params)
    end

    it "finds secret for app" do
      @mauthIncomingMiddleware.should_receive(:secret_for_app).with(@params[:app_uuid])
    end

    it "verifies with MAuth::Signer" do
      @signer = mock(MAuth::Signer)
      MAuth::Signer.stub(:new).and_return(@signer)
      @signer.should_receive(:verify).with(@digest, @params)
    end
  end

  describe "#authenticate_remotely" do
    before(:each) do
      @authentication_url = @mauthIncomingMiddleware.send(:authentication_url)

      @digest = "6327c1af329ba52478ad9ade1276d9b5b45962fb"
      @params = {
        :app_uuid    => "originator_app_uuid",
        :digest      => @digest,
        :verb        => "GET",
        :request_url => "/studies",
        :time        => 123,
        :post_data   => ''
      }
      @data = {
        'verb' => @params[:verb],
        'app_uuid' => @params[:app_uuid],
        'client_signature' => @params[:digest],
        'request_url' => @params[:request_url],
        'request_time' => @params[:time],
        'b64encoded_post_data' => Base64.encode64(@params[:post_data])
      }

      @request = mock(Net::HTTPRequest)
      @request.stub(:body)
      @response = mock(Net::HTTPResponse)
      @response.stub(:code).and_return("204")
      @http = mock(Net::HTTP)
      @http.stub(:use_ssl=)
      Net::HTTP.stub(:new).and_return(@http)
      Net::HTTP::Post.stub(:new).and_return(@request)
      @http.stub(:start).and_return(@response)
    end

    it "calls generic post" do
      @mauthIncomingMiddleware.should_receive(:post).with(@authentication_url, {"authentication_ticket" => @data})
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params)
    end

    it "returns false if post response is nil" do
      @mauthIncomingMiddleware.stub(:post).and_return(nil)
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params).should == false
    end

    it "returns true if post response is 204" do
      @mauthIncomingMiddleware.stub(:post).and_return(@response)
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params).should == true
    end

    it "returns false if post response not 204" do
      @response.stub(:code).and_return("412")
      @mauthIncomingMiddleware.stub(:post).and_return(@response)
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params).should == false
    end

    it "logs if post response not 204" do
      @response.stub(:code).and_return("412")
      @mauthIncomingMiddleware.stub(:post).and_return(@response)
      @mauthIncomingMiddleware.should_receive(:log)
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params).should
    end

    describe "post" do
      before(:each) do
         @request.stub(:body=)
      end
      it "creates http object with authentication_ticket url" do
        Net::HTTP.should_receive(:new).with(@authentication_url.host, @authentication_url.port).and_return(@http)
        @mauthIncomingMiddleware.send(:post, @authentication_url, {"authentication_ticket" => @data})
      end

      it "sets use of ssl based on url scheme" do
        @http.should_receive(:use_ssl=).with(@authentication_url.scheme == 'https')
        @mauthIncomingMiddleware.send(:post, @authentication_url, {"authentication_ticket" => @data})
      end

      it "makes a post object" do
        Net::HTTP::Post.should_receive(:new).with(@authentication_url.path, { 'Content-Length' => '205','Content-Type' => 'application/json'}).and_return(@request)
        @mauthIncomingMiddleware.send(:post, @authentication_url, {"authentication_ticket" => @data})
      end

      it "sets the body of the request" do
        @request.should_receive(:body=).with({"authentication_ticket" => @data}.to_json)
        @mauthIncomingMiddleware.send(:post, @authentication_url, {"authentication_ticket" => @data})
      end

      context "exception thrown" do
        it "writes to log when exception is rescued" do
          [Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].each do |exc|
            @mauthIncomingMiddleware.should_receive(:log)
            @http.stub(:start).and_raise(exc)
            @mauthIncomingMiddleware.send(:post, @authentication_url, {:authentication_ticket => @data})
          end
        end

        it "returns nil when exception is rescued" do
          [Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].each do |exc|
            @mauthIncomingMiddleware.should_receive(:log)
            @http.stub(:start).and_raise(exc)
            @mauthIncomingMiddleware.send(:post, @authentication_url, 'data' => @data.to_json).should == nil
          end
        end
      end
    end
  end

  describe "#secret_for_app" do
    before(:each) do
      @app_uuid = "originator_app_uuid"
    end

    it "refreshes cache if cached expired" do
      @mauthIncomingMiddleware.stub(:token_expired?).and_return(true)
      @mauthIncomingMiddleware.should_receive(:refresh_token)
      @mauthIncomingMiddleware.send(:secret_for_app, @app_uuid)
    end
  end

  describe "#fetch_app_uuid" do
    it 'fetches a hash based on a the key passed in' do
      dummy_pair = {'dummy_app'=> {:private_key => 'key'}}
      @mauthIncomingMiddleware.send(:synch_cache, dummy_pair, 'dummy_app')
      @mauthIncomingMiddleware.send(:fetch_app_uuid, 'dummy_app').should include(:private_key)
    end

    it 'returns nil when no key for an app uuid can be found' do
      dummy_pair = nil
      @mauthIncomingMiddleware.send(:synch_cache, dummy_pair, 'dummy_app')
      @mauthIncomingMiddleware.send(:fetch_app_uuid, 'dummy_app').should be_nil
    end
  end

  describe "#fetch_private_key" do
    it "fetches the value of an app's private key" do
      dummy_pair = {'dummy_app'=> {:private_key => 'key'}}
      @mauthIncomingMiddleware.send(:synch_cache, dummy_pair, 'dummy_app')
      @mauthIncomingMiddleware.send(:fetch_private_key, 'dummy_app').should include('key')
    end

    it "returns nil when no app can be found" do
      dummy_pair = nil
      @mauthIncomingMiddleware.send(:synch_cache, dummy_pair, 'dummy_app')
      @mauthIncomingMiddleware.send(:fetch_private_key, 'dummy_app').should be_nil
    end

    it " returns nil when an app does not have a private key" do
      dummy_pair = {'dummy_app' => {:last_refresh => Time.now}}
      @mauthIncomingMiddleware.send(:synch_cache, dummy_pair, 'dummy_app')
      @mauthIncomingMiddleware.send(:fetch_private_key, 'dummy_app').should be_nil
    end
  end

  describe "#parse_secret" do
    it "calls JSON.parse" do
      JSON.stub(:parse).and_return([])
      JSON.should_receive(:parse).with(@secret_from_mauth)
      @mauthIncomingMiddleware.send(:parse_secret, @secret_from_mauth)
    end

    it "returns parsed data in hash" do
      @mauthIncomingMiddleware.send(:parse_secret, @secret_from_mauth).should == @parsed_secret_from_mauth
    end

    context "JSON parse throws exception" do
      before(:each) do
        @mauthIncomingMiddleware.stub(:can_log?).and_return(true)
        @mauthIncomingMiddleware.stub(:log)
      end

      it "logs if possible" do
        [JSON::ParserError, TypeError].each do |exc|
          JSON.stub(:parse).and_raise(exc)
          @mauthIncomingMiddleware.should_receive(:log)
          @mauthIncomingMiddleware.send(:parse_secret, @secret_from_mauth)
        end
      end

      it "returns nil" do
        JSON.stub(:parse).and_raise(JSON::ParserError)
        @mauthIncomingMiddleware.send(:parse_secret, @secret_from_mauth).should == nil
      end
    end
  end

  describe "#get_remote_secret" do
    before(:each) do
      @request = mock(Net::HTTPRequest)
      @response = mock(Net::HTTPResponse)
      @response.stub(:code).and_return("200")
      @response.stub(:body).and_return(@secret_from_mauth)
      @http = mock(Net::HTTP)
      @http.stub(:use_ssl=)
      @http.stub(:read_timeout=)
      Net::HTTP.stub(:new).and_return(@http)
      Net::HTTP::Get.stub(:new).and_return(@request)
      @http.stub(:start).and_return(@response)
      @sec_tok_url = @mauthIncomingMiddleware.send(:security_token_url, 'dummy_app')
    end

    it "calls get" do
      @mauthIncomingMiddleware.should_receive(:get)
      @mauthIncomingMiddleware.send(:get_remote_secret, 'dummy_app')
    end

    describe "get" do
      it "creates an http object with appropriate parameters" do
        Net::HTTP.should_receive(:new).with(@sec_tok_url.host, @sec_tok_url.port).and_return(@http)
        @mauthIncomingMiddleware.send(:get, @sec_tok_url)
      end

      it "sets ssl to true" do
        @http.should_receive(:use_ssl=).with(@sec_tok_url.scheme == 'https')
        @mauthIncomingMiddleware.send(:get, @sec_tok_url)
      end

      it "sets read_timeout" do
        @http.should_receive(:read_timeout=)
        @mauthIncomingMiddleware.send(:get, @sec_tok_url)
      end

      it "formulates the request" do
         Net::HTTP::Get.should_receive(:new).and_return(@request)
         @mauthIncomingMiddleware.send(:get, @sec_tok_url)
      end

      it "asks MAuth for updated private keys" do
        @http.should_receive(:start)
        @mauthIncomingMiddleware.send(:get, @sec_tok_url)
      end

      it "returns response" do
        @response.stub(:code).and_return("200")
        @mauthIncomingMiddleware.send(:get, @sec_tok_url).should == @response
      end

      it "writes to log and return nil if exception is thrown" do
        [Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].each do |exc|
          @http.stub(:start).and_raise(exc)
          @mauthIncomingMiddleware.should_receive(:log)
          @mauthIncomingMiddleware.send(:get, @sec_tok_url).should == nil
        end
      end
    end

  end
  describe "protected methods" do
    it "returns the authentication url" do
      @mauthIncomingMiddleware.send(:authentication_url).path.should == "/mauth/v1/authentication_tickets.json"
      @mauthIncomingMiddleware.send(:authentication_url).host.should == "localhost"
      @mauthIncomingMiddleware.send(:authentication_url).scheme.should == "http"
    end

    it "returns the security token path" do
      @mauthIncomingMiddleware.send(:security_token_path, "dummy_app").should == "/mauth/v1/security_tokens/dummy_app.json"
    end

    it "returns the security token url" do
      @mauthIncomingMiddleware.send(:security_token_url, "dummy_app").path.should == "/mauth/v1/security_tokens/dummy_app.json"
      @mauthIncomingMiddleware.send(:security_token_url, "dummy_app").host.should == "localhost"
      @mauthIncomingMiddleware.send(:security_token_url, "dummy_app").scheme.should == "http"
    end
  end

end
