require File.dirname(__FILE__) + '/spec_helper'
    
describe "Medidata::MAuthMiddleware" do
  
  before(:each) do
    @app = mock
    config = {
      :mauth_baseurl => "http://localhost", 
      :app_uuid => "app_uuid", 
      :private_key => "secret" 
    }
    @mauthIncomingMiddleware = Medidata::MAuthMiddleware.new(@app, config)
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
      
      #it "should return false if app_uuid is not present" do
      #  @env['HTTP_AUTHORIZATION'] = "MWS :digest"
      #  @mauthIncomingMiddleware.send(:authenticated?, @env).should == false
      #end

      it "should return false if digest is not present" do
        @env['HTTP_AUTHORIZATION'] = "MWS app_uuid:"
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
      @response = mock
      @response.stub(:code).and_return("201")
      Net::HTTP.stub(:post_form).and_return(@response)
    end
    
    after(:each) do
      @mauthIncomingMiddleware.send(:authenticate_remotely, @digest, @params)
    end
    
    it "should make a post request to MAuth's authenication url with correct post data" do
      Net::HTTP.should_receive(:post_form).with(@mauthIncomingMiddleware.send(:authentication_url), "data" => @data.to_json)
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
      @response = mock(Net::HTTPResponse)
      @response.stub(:code).and_return("201")
      @response.stub(:body).and_return('[{"security_token":{"private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQCgQVbcBY2pcb8+T6E7QIdvzT9rXYAOqaz33WbPaKxWIhi3YOV+\nsRSxQamP5ATkbffGuZhuE1UQgBJB5ExNYtWwi7OI2TylYgE1m4jdgXVmkEuD/V5i\nCXnHE5TD4WV9cQLdGIDksDijJknHoVhm0mH/tU68BOatbLIXKur1kMbT7wIDAQAB\nAoGAUHYd72CWbPIgjF+c20wd9EOASR7r8fC9WMIAIbkzdheugzwSXhb5BbqrMQTS\ndALGui9rWjE4r40uHYlLyjsKgMtdDOsPX1lv2sViJPvsXwPfCTRJ9EcM1D2jghwM\n+mu9iAi+GCuqI7i2GugHhPjdYipKY+RQo1TDoX43sO29StkCQQDP6u5Uv1N+KMxB\nCgWqB4aA2ZmNK8LIrpQzUdXDYMAHLhxLR9L5dPNt71CUlhp0T0bbjcRomcpKAMgI\n2YvJvXE9AkEAxVC2Ro8GH1JYbiH+e+8X4TdLCCmnt7mxCEyUSwpgb+hYSIrSYwax\nOwjxEeP0V4UGc1l2B5UAqEpkxTZt3cyUmwJBAKrLxnR/psqgIQncfcKq4+a82dKJ\n/Dx2jO+LbhpNQ/GiA0QkAD9DvySzznIAzEJ3TTHWR13V18Lq2WfLrXVP1dECQQCl\n9Vb6Tb2mhooeR7VV5Cm/odQYD4EjhKmkA1UPMLEgLtpiWXDPHYff0YuBsquHGTnt\ntycRBYBCDCBpx3fs/+9VAkEAzytji96QArwJVg2pNQNAh3FHFhJs5p7woJUTMaWS\nERqRPZCFjDPGXwnPWIt16iSeuD8AI7YknsZgLddhLS6hfw==\n-----END RSA PRIVATE KEY-----\n","app_uuid":"5ff4257e-9c16-11e0-b048-0026bbfffe5e"}},{"security_token":{"private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDGS0ViRQviqd9ZkNam4Wgft552YQ2jlMdNyO9gdXrPRFog/TLU\nB4uD4GNtJyVr8QdUr2k8cqfHlrC9ZPZDObSA1NrrMTvEs7xgISdhC7/dX0jb5r9b\n3M3w/AlcAyZ6zVfwNsd2cQleio0lkWHjxssyQmT6dT6aGV9D5mjO12L0IwIDAQAB\nAoGAUQlr5pgvHker9m+BuZt+sQ+aW+iX6VUhCkHmyfXY5aGab8bqIcqfkpp+J5qK\n6Y0MIOi6yjBVLvT/b7c2CQ0pHY/ayaFLLZqp9HaEa3BEFook9TunwGpFE0E0xw6b\n9ofXUiOD/uVPjguOhSVLcBKRenscL5PPqpK/vpJKgstcKuECQQD+cWI8v+Mk0X4N\nLu7q9tgJLcO8c5bCjYnWCxE32ayr1LO7rUII88FytN57IJUaXXtZSm7vYCiWfc5L\n1kb8lD0RAkEAx4HsUoUzj3niN4TZHyymHUR1iM8BNumINTgqSFxTmGjnQEUM91Ii\nJzf/UzF5qq8GoXenyW8pd2N6WCkXnOEt8wJAYwGBhTvxSZlOoBicFMd6JpAtMr4T\ncp6afLQPvhiwLKh2S1fOcydOJbElROnXusuXPJZO9kwHXw+S30WAl7Wi0QJAZWe9\nVchMh8281NlafsTz/gZQ82O8S0vyJpLQswzylJIlkH5Ic+E0aNjGl2ObYs0pwqKO\nDw3Idt2CTxM75Ep0TwJBAJDQdHxOfal5Wux4ZAFr3pi7AQsImpv9KEOMC9x3NRSz\nY5UTY1i47AbSMU44oA3l9vfVLzLTxXnQvWV3PmygW4E=\n-----END RSA PRIVATE KEY-----\n","app_uuid":"6ff4257e-9c16-11e0-b048-0026bbfffe5f"}}]')
      Net::HTTP.stub(:start).and_return(@response)
    end
        
    it "should ask MAuth for updated private keys" do
      sec_tok_url = @mauthIncomingMiddleware.send(:security_tokens_url)
      Net::HTTP.should_receive(:start).with(sec_tok_url.host, sec_tok_url.port)
      @mauthIncomingMiddleware.send(:refresh_cache)
    end
  end
  
end