require File.dirname(__FILE__) + '/spec_helper'
    
describe "Medidata::MAuthMiddleware" do
  
  before(:each) do
    @app = mock
    @app.stub(:call)
    config = {
      :mauth_baseurl => "http://localhost", 
      :app_uuid => "app_uuid", 
      :private_key => "secret" 
    }
    @mauthIncomingMiddleware = Medidata::MAuthMiddleware.new(@app, config)
    @secrets_from_mauth = [{"security_token" => {"private_key" => "shhhhhhh", "app_uuid" => "5ff4257e-9c16-11e0-b048-0026bbfffe5e"}}, 
                           {"security_token" => {"private_key" => "shhh2", "app_uuid" => "6ff4257e-9c16-11e0-b048-0026bbfffe5f"}}].to_json
    @parsed_secrets_from_mauth = {"6ff4257e-9c16-11e0-b048-0026bbfffe5f"=>"shhh2", "5ff4257e-9c16-11e0-b048-0026bbfffe5e"=>"shhhhhhh"}   
  end
  
  describe "initialize" do
    it "should raise exception if no config given" do
      lambda { Medidata::MAuthMiddleware.new(@app, nil) }.should raise_error Medidata::MAuthMiddleware::MissingBaseURL
    end
    
    it "should raise exception if no mauth baseurl given in config" do
      lambda { Medidata::MAuthMiddleware.new(@app, {}) }.should raise_error Medidata::MAuthMiddleware::MissingBaseURL
    end
  end
  
  describe "should_authenticate?" do
    context "no whitelist" do
      it "should return true if no url_whitelist is defined" do
        @mauthIncomingMiddleware.send(:should_authenticate?, @env).should == true
      end
    end
    
    context "whitelist defined" do
      before(:each) do
        @base_config = {
          :mauth_baseurl => "http://localhost", 
          :app_uuid => "app_uuid", 
          :private_key => "secret" 
        }
        
        @base_env = {
          'HTTP_AUTHORIZATION' => "MWS app_uuid:digest", 
          'REQUEST_METHOD' => 'GET', 
          'REQUEST_URI' => 'example.com', 
          'HTTP_X_MWS_TIME' => 123
        }
      end
      
      it "should return true if path info matches regex in whitelist" do
        config = @base_config.merge(:path_whitelist => [/^\/v2\/api/, /^\/api\/v2/])
        env = @base_env.merge('PATH_INFO' => '/api/v2/studies.json')
        
        mauthIncomingMiddleware2 = Medidata::MAuthMiddleware.new(@app, config)
        mauthIncomingMiddleware2.send(:should_authenticate?, env).should == true
      end
      
      it "should return false if path info does not match any regex in whitelist" do
        config = @base_config.merge(:path_whitelist => [/^\/v2\/api/, /^\/api\/v2/])
        env = @base_env.merge('PATH_INFO' => '/api/v1/studies.json')
        
        mauthIncomingMiddleware2 = Medidata::MAuthMiddleware.new(@app, config)
        mauthIncomingMiddleware2.send(:should_authenticate?, env).should == false        
      end
      
      it "should return false if path info matches regex in whitelist but path info also matches exception" do
        config = @base_config.merge(:path_whitelist => [/^\/v2\/api/, /^\/api\/v2/], :whitelist_exceptions => [/^\/v2\/api\/request_tokens\.json/, /^\/api\/v2\/request_tokens\.json/])
        env = @base_env.merge('PATH_INFO' => '/api/v2/request_tokens.json')
        
        mauthIncomingMiddleware2 = Medidata::MAuthMiddleware.new(@app, config)
        mauthIncomingMiddleware2.send(:should_authenticate?, env).should == false
      end
      
      it "should return true if path info matches regex in whitelist and path info does not match any exception" do
        config = @base_config.merge(:path_whitelist => [/^\/v2\/api/, /^\/api\/v2/], :whitelist_exceptions => [/^\/v2\/api\/request_tokens\.json/, /^\/api\/v2\/request_tokens\.json/])
        env = @base_env.merge('PATH_INFO' => '/api/v2/sites.json')
        
        mauthIncomingMiddleware2 = Medidata::MAuthMiddleware.new(@app, config)
        mauthIncomingMiddleware2.send(:should_authenticate?, env).should == true
      end
      
    end
  end
  
  describe "call" do     
    before(:each) do
      @env = {'HTTP_AUTHORIZATION' => "MWS app_uuid:digest", 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => 'example.com', 'HTTP_X_MWS_TIME' => 123}
    end
        
    context "should authenticate" do
      before(:each) do
        @mauthIncomingMiddleware.stub(:should_authenticate?).and_return(true)
      end
      
      it "should call the app if authentication succeeded" do 
        @mauthIncomingMiddleware.stub(:authenticated?).and_return(true)  
        @app.should_receive(:call)
        @mauthIncomingMiddleware.call(@env)
      end

      it "should return 401 (Unauthorized) if authentication failed" do
        @mauthIncomingMiddleware.stub(:authenticated?).and_return(false)
        @mauthIncomingMiddleware.call(@env).should == [401, {"Content-Type"=>"text/plain"}, "Unauthorized"] 
      end
    end
    
    context "should not authenticate" do
      before(:each) do
        @mauthIncomingMiddleware.stub(:should_authenticate?).and_return(false)
      end
      
      it "should call the app" do    
        @app.should_receive(:call)
        @mauthIncomingMiddleware.call(@env)
      end
    end
  end
  
  describe "authenticated?" do
    before(:each) do
      @env = {'HTTP_AUTHORIZATION' => "MWS app_uuid:digest", 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => 'example.com', 'HTTP_X_MWS_TIME' => 123}
    end
    
    context "malformed header" do
      it "should return false if mws_token is not 'MWS'" do
        @env['HTTP_AUTHORIZATION'] = "MMM app_uuid:digest"
        @mauthIncomingMiddleware.send(:authenticated?, @env).should == false
      end
      
      it "should return false if app_uuid is not present" do
        @env['HTTP_AUTHORIZATION'] = "MWS"
        @mauthIncomingMiddleware.send(:authenticated?, @env).should == false
      end

      it "should return false if digest is not present" do
        @env['HTTP_AUTHORIZATION'] = "MWS"
        @mauthIncomingMiddleware.send(:authenticated?, @env).should == false
      end
      
    end
    
    it "should authenticate locally if configured to do so" do
      @mauthIncomingMiddleware.stub(:can_authenticate_locally?).and_return(true)
      @mauthIncomingMiddleware.should_receive(:authenticate_locally)
      @mauthIncomingMiddleware.send(:authenticated?, @env)
    end

    it "should authenticate remotely if configured to do so" do
      @mauthIncomingMiddleware.stub(:can_authenticate_locally?).and_return(false)
      @mauthIncomingMiddleware.should_receive(:authenticate_remotely)
      @mauthIncomingMiddleware.send(:authenticated?, @env)
    end    
  end
  
  describe "authenticate_locally" do
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
    
    it "should find secret for app" do
      @mauthIncomingMiddleware.should_receive(:secret_for_app).with(@params[:app_uuid])
    end
    
    it "should verify with MAuth::Signer" do
      @signer = mock(MAuth::Signer)
      MAuth::Signer.stub(:new).and_return(@signer)
      @signer.should_receive(:verify).with(@digest, @params)
    end
  end  

  describe "authenticate_remotely" do
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
      @request.stub(:set_form_data)
      @response = mock(Net::HTTPResponse)
      @response.stub(:code).and_return("204")
      @http = mock(Net::HTTP)
      @http.stub(:use_ssl=)
      Net::HTTP.stub(:new).and_return(@http)
      Net::HTTP::Post.stub(:new).and_return(@request)      
      @http.stub(:start).and_return(@response)
    end
    
    it "should call generic post" do
      @mauthIncomingMiddleware.should_receive(:post).with(@authentication_url, 'data' => @data.to_json)
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params)
    end
    
    it "should return true if post response is 204" do
      @mauthIncomingMiddleware.stub(:post).and_return(@response)
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params).should == true
    end

    it "should return false if post response not 204" do
      @response.stub(:code).and_return("412")
      @mauthIncomingMiddleware.stub(:post).and_return(@response)
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params).should == false
    end
    
    it "should return log if post response not 204" do
      @response.stub(:code).and_return("412")
      @mauthIncomingMiddleware.stub(:post).and_return(@response)
      @mauthIncomingMiddleware.should_receive(:log)
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params).should
    end
    
    describe "post" do
      it "should create http object with authentication_ticket url" do
        Net::HTTP.should_receive(:new).with(@authentication_url.host, @authentication_url.port).and_return(@http)
        @mauthIncomingMiddleware.send(:post, @authentication_url, 'data' => @data.to_json)
      end
    
      it "should set use ssl based on url scheme" do
        @http.should_receive(:use_ssl=).with(@authentication_url.scheme == 'https')
        @mauthIncomingMiddleware.send(:post, @authentication_url, 'data' => @data.to_json)
      end
    
      it "should make a post object" do
        Net::HTTP::Post.should_receive(:new).with(@authentication_url.path).and_return(@request)
        @mauthIncomingMiddleware.send(:post, @authentication_url, 'data' => @data.to_json)
      end
    
      it "should set the form data of the request" do
        @request.should_receive(:set_form_data).with("data" => @data.to_json)
        @mauthIncomingMiddleware.send(:post, @authentication_url, 'data' => @data.to_json)
      end

      context "exception thrown" do
        it "should call log when exception is rescued" do
          [Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].each do |exc|
            @mauthIncomingMiddleware.should_receive(:log)
            @http.stub(:start).and_raise(exc)
            @mauthIncomingMiddleware.send(:post, @authentication_url, 'data' => @data.to_json)
          end
        end
      
        it "should return nil when exception is rescued" do
          [Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].each do |exc|
            @mauthIncomingMiddleware.should_receive(:log)
            @http.stub(:start).and_raise(exc)
            @mauthIncomingMiddleware.send(:post, @authentication_url, 'data' => @data.to_json).should == nil
          end
        end
      end
    end
  end
  
  describe "secret_for_app" do
    before(:each) do
      @app_uuid = "originator_app_uuid"
    end
    
    it "should refresh cache if cached expired" do
      @mauthIncomingMiddleware.stub(:cache_expired?).and_return(true)
      @mauthIncomingMiddleware.should_receive(:refresh_cache)
      @mauthIncomingMiddleware.send(:secret_for_app, @app_uuid)
    end
  end
  
  describe "refresh_cache" do
    before(:each) do
      @body_value = "body"
      @mauthIncomingMiddleware.stub(:get_remote_secrets).and_return(@body_value)
      @mauthIncomingMiddleware.stub(:parse_secrets)
    end
    
    after(:each) do
      @mauthIncomingMiddleware.send(:refresh_cache)
    end
    
    it "should get_remote_secrets" do
      @mauthIncomingMiddleware.should_receive(:get_remote_secrets)
    end
    
    it "should parse the fetched secrets" do
      @mauthIncomingMiddleware.should_receive(:parse_secrets).with(@body_value)
    end
  
  end

  describe "parse_secrets" do
    it "should call JSON.parse" do
      JSON.stub(:parse).and_return([])
      JSON.should_receive(:parse).with(@secrets_from_mauth)
      @mauthIncomingMiddleware.send(:parse_secrets, @secrets_from_mauth)
    end
    
    it "should return parsed data in hash" do
      @mauthIncomingMiddleware.send(:parse_secrets, @secrets_from_mauth).should == @parsed_secrets_from_mauth
    end

    context "JSON parse throws exception" do
      before(:each) do
        @mauthIncomingMiddleware.stub(:can_log?).and_return(true)
        @mauthIncomingMiddleware.stub(:log)
      end
      
      it "should if possible write to log" do
        [JSON::ParserError, TypeError].each do |exc|
          JSON.stub(:parse).and_raise(exc)
          @mauthIncomingMiddleware.should_receive(:log)
          @mauthIncomingMiddleware.send(:parse_secrets, @secrets_from_mauth)
        end
      end
    
      it "should return nil" do
        JSON.stub(:parse).and_raise(JSON::ParserError)
        @mauthIncomingMiddleware.send(:parse_secrets, @secrets_from_mauth).should == nil
      end
    end
  end
  
  describe "get_remote_secrets" do
    before(:each) do
      @request = mock(Net::HTTPRequest)
      @response = mock(Net::HTTPResponse)
      @response.stub(:code).and_return("200")
      @response.stub(:body).and_return(@secrets_from_mauth)      
      @http = mock(Net::HTTP)
      @http.stub(:use_ssl=)
      @http.stub(:read_timeout=)
      Net::HTTP.stub(:new).and_return(@http)
      Net::HTTP::Get.stub(:new).and_return(@request)      
      @http.stub(:start).and_return(@response)
      @sec_tok_url = @mauthIncomingMiddleware.send(:security_tokens_url)
    end
        
    it "should create an http object with appropriate parameters" do
      Net::HTTP.should_receive(:new).with(@sec_tok_url.host, @sec_tok_url.port).and_return(@http)
      @mauthIncomingMiddleware.send(:get_remote_secrets)
    end

    it "should set ssl to true" do
      @http.should_receive(:use_ssl=).with(true)
      @mauthIncomingMiddleware.send(:get_remote_secrets)
    end

    it "should set read_timeout" do
      @http.should_receive(:read_timeout=)
      @mauthIncomingMiddleware.send(:get_remote_secrets)
    end
    
    it "should formulate the request" do
       Net::HTTP::Get.should_receive(:new).and_return(@request)
       @mauthIncomingMiddleware.send(:get_remote_secrets)
    end
    
    it "should ask MAuth for updated private keys" do
      @http.should_receive(:start)
      @mauthIncomingMiddleware.send(:get_remote_secrets)
    end
    
    it "should return nil and write to log if response code is not 200" do
      @response.stub(:code).and_return("404")
      @mauthIncomingMiddleware.should_receive(:log)
      @mauthIncomingMiddleware.send(:get_remote_secrets).should == nil
    end
    
    it "should return response body if response code is 200" do
      @response.stub(:code).and_return("200")
      @mauthIncomingMiddleware.send(:get_remote_secrets).should == @response.body
    end
    
    it "should write to log and return nil if exception is thrown" do
      [Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError,
       Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].each do |exc|
        @http.stub(:start).and_raise(exc)
        @mauthIncomingMiddleware.should_receive(:log)
        @mauthIncomingMiddleware.send(:get_remote_secrets).should == nil
      end
    end
    
  end
  
  describe "cache_expired?" do
    before(:each) do
      @body_value = []
      retval = []
      retval.stub(:body).and_return(@body_value)
      @mauthIncomingMiddleware.stub(:get_remote_secrets).and_return(retval)
      @mauthIncomingMiddleware.stub(:parse_secrets)
    end
    
    it "should return true first time it is called (cache has never been refreshed)" do
      @mauthIncomingMiddleware.send(:cache_expired?).should == true
    end 
    
    it "should return false immedidately after a cache reset" do
      @mauthIncomingMiddleware.send(:refresh_cache)
      @mauthIncomingMiddleware.send(:cache_expired?).should == false
    end
    
    it "should return true 61 seconds immediately after a cache reset" do
      @mauthIncomingMiddleware.send(:refresh_cache)
      Timecop.travel(Time.now + 61)
      @mauthIncomingMiddleware.send(:cache_expired?).should == true
      Timecop.return # "turn off" Timecop
    end
    
  end
  
end