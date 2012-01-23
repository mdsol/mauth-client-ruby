require File.dirname(__FILE__) + '/spec_helper'

describe "Medidata::MAuthMiddleware" do
  before(:each) do
    @app = mock
    @sample_config = {
      :mauth_baseurl => 'http://0.0.0.0:3000',
      :private_key => "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEApr1NrmTQPlwZ4XKSl3bmmDCu0j7ME1goC5YD/XAHqe5pkrEV\nVk6j8gP+Gi/3UypGM/JmzWGSTenDFApkys3VkO7kwOqcHVO1wXTZTKLSUheR3H1p\nN5ZyfUkHrw/LTOm+tA0tNnqQF2FjdGLnY8Pni/3IjyaocKo2i+oKFaxdMO6M9dF+\neQEgVloQcSFPi5gNwgTvAu2urfJKMx+p5LU44A1kqf9NT86sIscF84PssPGHm5IL\n7mFXBmwPFrr4NODp1BsXchFPVIVGVFfHjYnwQLuyFTwfCi2LTr9o7MMuXAJUdtQd\n9ihiuSJwWR+PTkmeNVCs1s30ejHUv3PDCBKXSwIDAQABAoIBADhBQBcpfjS74CN3\nA0xE2lHYgvL+Kt4P7RrTly8HgB5uCIJsanV+/MMnY7C0JC6T4bGfA94hIDpXNvDo\n/M6LmZVXdCg+P0OJvZWydanseScnOpf4W+pcQO5SGFyQ6JdfeW7Hz0xFF547xlE7\nGTRIoTNTATqC4Wt5kgOsh5B+Ycai+Yve89DT2DHHG0xDk6iMEgSO4iFSQhDnoIBJ\nGaJPU2r79q3AGVrHJZUQGmeiKxDNwjxjY9EEGXGTFbADf8lhK7qh/eTJeIRsQ1Wi\nZ1gCVxnzqJdIO7kfZHiVXocpePf0WTfZvM4XqXhUt6EiOXR5TaT5vB1BuNNmBvXQ\nxntDxBECgYEA3DoBNYVr74jsMbcUB1iRHzgSLMw2Z0pQ19SZeF91/tTU6PxGQwaa\nI7etgSzaXFmZ7B6IC64muiu00aQjltnBCIKqMyfOHIOTs79Xordoq5LUWuV0EC1z\nOXpSN4tADkpgHh+qr8yn55Nf+hnR0HpRE+OkTTW+VNN8Ooz80j1APnkCgYEAwdMR\nZDJrlEjYu82ql641P6WNHpSKBCR/6Y27aw7i1n44UDfika4ODiEwkJ+Rjf2+FVVC\n9kz9I9tkjBtoP7BN0ffRvyx607dV9MmRRhJrhDFLAkNZqYobMnE3ihXB+AcDU3rY\neD+cQAHmigwbkkSam2ek1dQZOIZomtXyw2gAQuMCgYAftG4WIXYvjvvKEHxerl5+\nKxlav6+ZYTaQS/goPz4CiOt5+0+2OI4aVEgzT5zELNYfCyo03EaRCNfIUqQZBJJo\nwj70jGd87WhnOUXJlDQKd2IBEAWMiq6K+NQ7UN3Q8N4zmAV/t6v4h9wKaostQ17G\nyUAPKYyUM7ovx7piHhVQqQKBgBls66oeJxiTmcLBDvDIzHll6SYqzBQRCaqEiiJY\nGI+UjSSQwCrmDzfxSKKgHALpV0cLITaYENjkTcNHURyRrxOtE5mlZxNgyGjNDD6J\n6gq0QKeyWA+yazDpwyRdCE3V9ay8v6q+hWusFCblwbQlRba/GNNn+Er+7rfo+uiB\nOw+LAoGARyRQ6azgTT1USjcENcWJYa9sUUQuAwJHfuay1R4j0ufinM/VciPAF08R\nLwT6kd5AqDZ7xyebqp7VrCwD7ttXEj5u+oDxUSUx+v2JV1nUggEoqejPuVGWg5ce\n2XHbr5ULf9PJioDJSs113I8kc7TaXmrNqS5LqMdaxev/XiC/tjg=\n-----END RSA PRIVATE KEY-----\n",
      :app_uuid => "blah",
      :mauth_api_version => 'v1',
    }
  end
  
  describe "call" do
    before(:each) do
      @env = mock
      @middlew = Medidata::MAuthMiddleware.new(@app, @sample_config)
    end
    
    context "middleware should authenticate" do
      before(:each) do
        @middlew.stub(:should_authenticate?).and_return(true)
      end
      
      it "should call app if authenticated" do
        @middlew.stub(:authenticated?).and_return(true)
        @app.should_receive(:call).with(@env)
        @middlew.call(@env)
      end
      
      it "should return unauthenticated response if not authenticated" do
        @middlew.stub(:authenticated?).and_return(false)
        @middlew.call(@env).should == [401, {"Content-Type"=>"text/plain"}, ["Unauthorized"]]
      end
    end
    
    context "middleware should not authenticate" do
      before(:each) do
        @middlew.stub(:should_authenticate?).and_return(false)
      end
      
      it "should call app directly if not asked to authenticate" do
        @app.should_receive(:call).with(@env)
        @middlew.call(@env)
      end
    end
  end
  
  describe "should_authenticate?" do
    before(:each) do
      class Medidata::MAuthMiddleware
        attr_reader :config # Monkey-patch for testing purposes
      end
      @env = {}
      @middlew = Medidata::MAuthMiddleware.new(@app, @sample_config)
    end
    
    context "@config.should_authentication_check is nil" do
      before(:each) do
        @middlew.config.stub(:should_authentication_check).and_return(nil)
      end
      
      it "should return true" do
        @middlew.send(:should_authenticate?, @env).should == true
      end
    end
    
    context "@config.should_authentication_check is not nil" do  
      it "should call" do
        @middlew.config.stub(:should_authentication_check).and_return(Proc.new{|env| true })
        @middlew.config.should_authentication_check.should_receive(:call).with(@env)
        @middlew.send(:should_authenticate?, @env)
      end
      
      it "should execute proc and return true when appropriate" do
        env = {:PATH_INFO => "/api/studies.json"}
        @middlew.config.stub(:should_authentication_check).and_return(Proc.new{|env| (env[:PATH_INFO] =~ /api/) != nil })
        @middlew.send(:should_authenticate?, env).should == true
      end
      
      it "should execute proc and return false when appropriate" do
        env = {:PATH_INFO => "/user/studies.json"}
        @middlew.config.stub(:should_authentication_check).and_return(Proc.new{|env| (env[:PATH_INFO] =~ /api/) != nil })
        @middlew.send(:should_authenticate?, env).should == false
      end
    end    
  end
      
  describe "can_authenticate_locally?" do 
    it "should return false if self_app_uuid is nil" do
      @sample_config.delete(:app_uuid)
      middlew = Medidata::MAuthMiddleware.new(@app, @sample_config)
      middlew.send(:can_authenticate_locally?).should == false
    end
    
    it "should return false if self_private_key is nil" do
      @sample_config.delete(:private_key)
      middlew = Medidata::MAuthMiddleware.new(@app, @sample_config)
      middlew.send(:can_authenticate_locally?).should == false
    end
    
    it "should return true if self_private_key and self_app_uuid are present" do
      middlew = Medidata::MAuthMiddleware.new(@app, @sample_config)
      middlew.send(:can_authenticate_locally?).should == true
    end
  end
  
  describe "authenticated?" do
    before(:each) do
      class Medidata::MAuthMiddleware
        attr_reader :mauth_verifiers_manager, :mauth_remote_verifier # Monkey-patch for testing purposes
      end
      
      @message_body = mock
      @message_body.stub(:read).and_return("message body")
      @message_body.stub(:rewind)
      @client_sig = "B"
      @client_app_uuid = "A"
      @env = {
        'HTTP_AUTHORIZATION' => "MWS #{@client_app_uuid}:#{@client_sig}",
        'REQUEST_METHOD' => 'POST',
        'PATH_INFO' => '/studies',
        'HTTP_X_MWS_TIME' => Time.now.to_i,
        'rack.input' => @message_body,
      }
      @middlew = Medidata::MAuthMiddleware.new(@app, @sample_config)
    end
    
    it "should return false if something other than MWS (case-sensitive) is given in Authorization header" do
      ['AWS', 'blah', 'mws'].each do | mws |
        @env['HTTP_AUTHORIZATION'] = "#{mws} foo:bar"
        @middlew.send(:authenticated?, @env).should == false
      end
    end
    
    it "should return false if app_uuid is nil in header" do
      @env['HTTP_AUTHORIZATION'] = "MWS :bar"
      @middlew.send(:authenticated?, @env).should == false
    end
    
    it "should return false if signature is nil in header" do
      ['foo', 'foo:'].each do |sig|
        @env['HTTP_AUTHORIZATION'] = "MWS #{sig}"
        @middlew.send(:authenticated?, @env).should == false
      end
    end
    
    context "can authenticate locally" do
      before(:each) do
        @middlew.stub(:can_authenticate_locally?).and_return(true)
      end
      
      it "should call @mauth_verifiers_manager.authenticate_request with appropriate args" do
        @middlew.mauth_verifiers_manager.should_receive(:authenticate_request).with(@client_sig, {:app_uuid=>@client_app_uuid, :digest=>@client_sig, :verb=>@env['REQUEST_METHOD'], :request_url=>@env['PATH_INFO'], :time=>@env['HTTP_X_MWS_TIME'], :body=>"message body"})
        @middlew.send(:authenticated?, @env)
      end
    end
    
    context "cannot authenticate locally" do
      before(:each) do
        @middlew.stub(:can_authenticate_locally?).and_return(false)
      end
      
      it "should call @mauth_remote_verifier.authenticate_request with appropriate args" do
        @middlew.mauth_remote_verifier.should_receive(:authenticate_request).with(@client_sig, {:app_uuid=>@client_app_uuid, :digest=>@client_sig, :verb=>@env['REQUEST_METHOD'], :request_url=>@env['PATH_INFO'], :time=>@env['HTTP_X_MWS_TIME'], :body=>"message body"})
        @middlew.send(:authenticated?, @env)
      end
    end
    
  end
end

describe "Medidata::MAuthMiddlewareConfig" do
  it "should raise if there is no mauth_baseurl in config" do
    lambda { Medidata::MAuthMiddlewareConfig.new(:mauth_api_version => 'v1') }.should raise_error(ArgumentError, 'mauth_baseurl: missing base url')
  end
  
  it "should raise if there is no mauth_api_version in config" do
    lambda { Medidata::MAuthMiddlewareConfig.new(:mauth_baseurl => 'https://sandbox.mauth.net') }.should raise_error(ArgumentError, 'mauth_api_version: missing api mauth_api_version')
  end
  
  it "should raise if mauth_baseurl is not valid url" do
    lambda { Medidata::MAuthMiddlewareConfig.new(:mauth_baseurl => 'blah', :mauth_api_version => 'v1') }.should raise_error(ArgumentError, 'mauth_baseurl: blah must contain a scheme and host')
  end 
end

describe "Medidata::MAuthVerifiersManager" do  
  describe "initialize" do
    context "no config" do
      it "should raise error" do
        lambda { Medidata::MAuthVerifiersManager.new }.should raise_error(ArgumentError, 'must provide an MAuthMiddlewareConfig')
      end
    end
    
    context "config given" do
      before(:each) do
        @config = mock(Medidata::MAuthMiddlewareConfig)
        @config.stub(:self_private_key).and_return("blah")
        MAuth::Signer.stub(:new)
      end
      
      after(:each) do
        Medidata::MAuthVerifiersManager.new(@config)
      end
      
      it "should make mauth_signer_for_self" do
        MAuth::Signer.should_receive(:new).with(:private_key => @config.self_private_key)
      end      
    end
  end
  
  describe "authenticate_request" do
    before(:each) do
      @config = mock(Medidata::MAuthMiddlewareConfig)
      @config.stub(:self_private_key).and_return("blah")
      MAuth::Signer.stub(:new)
      Medidata::MAuthVerifiersManager.new(@config)
      @verifiers_manager = Medidata::MAuthVerifiersManager.new(@config)
    end
    
    it "should try to find verifier for app" do
      @verifiers_manager.should_receive(:verifier_for_app).with("auuid")
      @verifiers_manager.authenticate_request("foo", {:app_uuid => "auuid"})
    end
    
    it "should return true if verifier can be found and request is authentic" do
      @verifier = mock(Hash)
      @verifier.stub(:verify_request).and_return(true)
      @verifiers_manager.stub(:verifier_for_app).and_return(@verifier)
      @verifiers_manager.authenticate_request("foo", {}).should == true
    end
    
    it "should return false if verifier cannot be found (i.e. is nil)" do
      @verifiers_manager.stub(:verifier_for_app).and_return(nil)
      @verifiers_manager.authenticate_request("foo", {}).should == false
    end
  
    it "should return false if verifier is found but request is not authentic" do
      @verifier = mock(Hash)
      @verifier.stub(:verify_request).and_return(false)
      @verifiers_manager.stub(:verifier_for_app).and_return(@verifier)
      @verifiers_manager.authenticate_request("foo", {}).should == false
    end
  end
  
end

describe "Medidata::MAuthRemoteVerifier" do
  describe "initialize" do
    context "no config" do
      it "should raise error" do
        lambda { Medidata::MAuthRemoteVerifier.new }.should raise_error(ArgumentError, 'must provide an MAuthMiddlewareConfig')
      end
    end
  end
  
  describe "authenticate_request" do
    before(:each) do
      @config = mock(Medidata::MAuthMiddlewareConfig)
      @config.stub(:mauth_baseurl).and_return("http://example.com")
      @config.stub(:mauth_api_version).and_return("v1")
      @config.stub(:log)
      @mauth_remote_verifier = Medidata::MAuthRemoteVerifier.new(@config)
      @digest = "sig"
      @params = {
        :verb => "GET",
        :app_uuid => "auuid",
        :request_url => "/studies",
        :time => Time.now.to_i,
        :body => "hello=there",
        
      }
    end
    
    it "should post to authentication url with correct data" do
      data = {
        'verb' => @params[:verb],
        'app_uuid' => @params[:app_uuid],
        'client_signature' => @digest,
        'request_url' => @params[:request_url],
        'request_time' => @params[:time],
        'b64encoded_body' => Base64.encode64(@params[:body])
      }
      @mauth_remote_verifier.should_receive(:post).with(
        @mauth_remote_verifier.send(:authentication_url),
        {"authentication_ticket" => data}
      )
      @mauth_remote_verifier.authenticate_request(@digest, @params)
    end
    
    it "should return false if response is nil" do
      @mauth_remote_verifier.stub(:post).and_return(nil)
      @mauth_remote_verifier.authenticate_request(@digest, @params).should == false
    end
    
    it "should log if response is nil" do
      @mauth_remote_verifier.stub(:post).and_return(nil)
      @config.should_receive(:log).with("Remote authen. returned nil response")
      @mauth_remote_verifier.authenticate_request(@digest, @params)
    end
    
    it "should return false if response code is not 204" do
      @response = mock
      @response.stub(:code).and_return("500")
      @mauth_remote_verifier.stub(:post).and_return(@response)
      @mauth_remote_verifier.authenticate_request(@digest, @params).should == false
    end
    
    it "should log if response code is not 204" do
      @response = mock
      @response.stub(:code).and_return("500")
      @mauth_remote_verifier.stub(:post).and_return(@response)
      @config.should_receive(:log).with("Attempt to authenticate remotely failed with status code 500")
      @mauth_remote_verifier.authenticate_request(@digest, @params)
    end
    
    it "should return true if response code is 204" do
      @response = mock
      @response.stub(:code).and_return("204")
      @mauth_remote_verifier.stub(:post).and_return(@response)
      @mauth_remote_verifier.authenticate_request(@digest, @params).should == true
    end
    
    it "should not log if response code is 204" do
      @response = mock
      @response.stub(:code).and_return("204")
      @mauth_remote_verifier.stub(:post).and_return(@response)
      @config.should_not_receive(:log)
      @mauth_remote_verifier.authenticate_request(@digest, @params).should
    end
  end
  
  describe "post" do
    before(:each) do
      @config = mock(Medidata::MAuthMiddlewareConfig)
      @config.stub(:mauth_baseurl).and_return("http://example.com")
      @config.stub(:mauth_api_version).and_return("v1")
      @mauth_remote_verifier = Medidata::MAuthRemoteVerifier.new(@config)
      @authentication_url = @mauth_remote_verifier.send(:authentication_url)
    end   
    
    it "should post with RestClient, sending several arguments" do
      rcr = mock(RestClient::Resource)
      resp = mock
      resp.stub(:net_http_res)
      post_data = "blah"
      RestClient::Resource.should_receive(:new).with(@authentication_url.to_s, {:timeout => 2, :verify_ssl => (OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT)}).and_return(rcr)
      rcr.should_receive(:post).with(post_data.to_json, :content_type => 'application/json').and_return(resp)
      resp.should_receive(:net_http_res)
      @mauth_remote_verifier.send(:post, @authentication_url, post_data)
    end
  end
  
end

