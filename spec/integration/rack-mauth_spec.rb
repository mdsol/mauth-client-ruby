require 'rack/test'
require 'rack/mauth'

# NOTE:  In order for these tests to pass, the APP_UUID and PUBLIC_KEY given below must exist as a security token
# in the persistent store of the specified MAUTH_BASE_URL
MAUTH_BASE_URL = "https://mauth-sandbox.imedidata.net"
APP_UUID = "testing_hands_off"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2GhmijLqVmuT2D7H0wLfq4LIJ6fpHMyl5Tz1mytNz4/pa0fI\nzxabMDBpC9hhLkzNUPoOFcI9Cz2aEIW+HHqkxCcifmqXEF5MlQz1OHJYKKFXvEPu\nWNlILCtCiRosw5xwZDrVntufPhsUWTTiHpG9VHdK79VnUVD65yA8f9ma9Gwsx9/A\nRpetEpzttm+183nY6adGytmK32F8l58DmGyV5lGHcouyhddMwLD2VDJm6hlMqlN7\nJrn7YdzcHCWrUUkan7zwlS/d/AGN9gjFHKa6dJvyTAONTD4s2SHNifhv79eeu1Az\nNlTIb9X0ZgRPPRh/6NfVLsmj6ScVloW2Bf7VHQIDAQABAoIBAHJT3XA/a9vSI55H\ntIu+5emXQyToKVhkqXQNG3gpjYcNcXSSzPzS5ZO0z5pJazXpr0KLiGtoXZWVqtH1\nxjUHegqC3k9JApvMJctMuDRk/Dwi2NYGUWIxEFb9V75UzLde62WYS4kMX/mQltR2\nAsvBlPONvlIsPNQR4yu9tRiaHqnnj1ITUWLhndfjQBTEgqXF948m2Ltc6ub/cHj3\nsDglxyjteH9QyiZUk7hUVOpMla16uFosOX5crsoMNrul6dHLRcTcr4YVutAQ0/uF\nMKB06GiOWMIOUPDvd5rYcrsamy2IcZaz3M/SKmePBPEF/nbM0dVS3yfbj4uCQXZ9\nSQmb4oUCgYEA933iN5pXYp6dZmEyjrvcFRNpw2pbIq6KU+2sg5YEL3c4rpA7ABbT\nEOhUUIg8uJM+AcGQSp1EoBPQLXFbCwxftqz/vKuXxR458GuTOGCVIQh++RE1aunK\nEJ84q4Uta6O3XLHIRvhMTsbV4iVQTblRqPRd7+z8KJNGXVzs43cF93MCgYEA39j0\nZD3Soi2otZi9tzvuBgxzFyhn8Tkcm0YuBvUMCGweusjxzMUbJ5JbFfFzWxVKrQ6Z\nrrtwqQ+54RonciuSbwQTEMznYCcX3IFGTxCCx3fg9GfoWmvbCYKGq8sJXD1e2qOy\ny+GlaOKnrjo0UQm5GNk/GlUpfSV+UGTYjeRQPS8CgYBX0rvrr0FDJbYFFoiyTceT\nUwg86AjfDcDYd4a4SwvBLDVY/KVzKqZLYaZJzY5+kQF37hAd6iDoDR/agFcmXIW6\ndTlq4hlBQbCduA7N+rfwuOsVxx2FiuDBdT7O3rt3bukqY4wGYyXw7m4HieYtLo3j\nvpN3CEmSvHBDwS3uqdXcMQKBgHDfHuxk2A764vUenZsFVxIpuObWcwMJf0k0bAUK\nDxU4H46jwHk2cmjTvaYk57vn0o3MrOWUkkxNJ7c/zuAc5GuiLFLuX0T2sWt4rBE2\nDBu0cPQMaPcfJ4V2EZ4SdRfTwj6RCJkRoKxwjYimxLaQJotHEDCg/JikDTtQfnmd\nxG/1AoGBAOcgAo/ROELsh/DZEcHYLUSeCUYU7bMBzASYNZPwyJsIgLSWgiRFUD3I\nN33J/5/IkkupRzXo1DwOQO5JF2a3OPEY3LENq7YmjzHj1/KAfehvl+K1qtt7Ian5\nPdfW9FmUnq0G0+Y0JCodMk1g9u9h3klTZ6ah3PHlcwmNjmKRVX3n\n-----END RSA PRIVATE KEY-----\n"
PUBLIC_KEY = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA2GhmijLqVmuT2D7H0wLfq4LIJ6fpHMyl5Tz1mytNz4/pa0fIzxab\nMDBpC9hhLkzNUPoOFcI9Cz2aEIW+HHqkxCcifmqXEF5MlQz1OHJYKKFXvEPuWNlI\nLCtCiRosw5xwZDrVntufPhsUWTTiHpG9VHdK79VnUVD65yA8f9ma9Gwsx9/ARpet\nEpzttm+183nY6adGytmK32F8l58DmGyV5lGHcouyhddMwLD2VDJm6hlMqlN7Jrn7\nYdzcHCWrUUkan7zwlS/d/AGN9gjFHKa6dJvyTAONTD4s2SHNifhv79eeu1AzNlTI\nb9X0ZgRPPRh/6NfVLsmj6ScVloW2Bf7VHQIDAQAB\n-----END RSA PUBLIC KEY-----\n"

describe 'Local Authentication with Rack-Mauth' do
  include Rack::Test::Methods

  def app
    mini_app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, ["Hello World"]] }
    
    config = {
      :mauth_baseurl => MAUTH_BASE_URL,
      :private_key => PRIVATE_KEY,
      :app_uuid => APP_UUID,
      :mauth_api_version => 'v1'
    }

    @mware = Medidata::MAuthMiddleware.new(mini_app, config)
  end

  describe "proper signatures provided by client" do
    it "should return 200 if GET request is properly signed" do
      #Note, in this case, client making call to app has same private key as app
      #This is not the normal state of affairs
      headers = MAuth::Signer.new(:private_key => PRIVATE_KEY).signed_request_headers(
        :app_uuid => APP_UUID,
        :request_url => '/',
        :verb => "GET")
      headers.each{ |k,v| header(k,v) }
      get '/'
      last_response.should be_ok
      last_response.body.should == 'Hello World'
    end
    
    it "should return 200 if POST request is properly signed" do
      #Note, in this case, client making call to app has same private key as app
      #This is not the normal state of affairs
      headers = MAuth::Signer.new(:private_key => PRIVATE_KEY).signed_request_headers(
        :app_uuid => APP_UUID,
        :request_url => '/',
        :verb => "POST",
        :body => "blah")
      headers.each{ |k,v| header(k,v) }
      post '/', "blah"
      last_response.should be_ok
      last_response.body.should == 'Hello World'
    end
    
    it "should return 200 if PUT request is properly signed" do
      #Note, in this case, client making call to app has same private key as app
      #This is not the normal state of affairs
      headers = MAuth::Signer.new(:private_key => PRIVATE_KEY).signed_request_headers(
        :app_uuid => APP_UUID,
        :request_url => '/',
        :verb => "PUT",
        :body => "blah")
      headers.each{ |k,v| header(k,v) }
      put '/', "blah"
      last_response.should be_ok
      last_response.body.should == 'Hello World'
    end
    
    it "should return 200 if DELETE request is properly signed" do
      #Note, in this case, client making call to app has same private key as app
      #This is not the normal state of affairs
      headers = MAuth::Signer.new(:private_key => PRIVATE_KEY).signed_request_headers(
        :app_uuid => APP_UUID,
        :request_url => '/',
        :verb => "DELETE")
      headers.each{ |k,v| header(k,v) }
      delete '/'
      last_response.should be_ok
      last_response.body.should == 'Hello World'
    end
  end
  
  describe "improper information provided by client" do
    it "should return 401 if incorrect signature" do
      headers = MAuth::Signer.new(:private_key => PRIVATE_KEY).signed_request_headers(
        :app_uuid => APP_UUID,
        :request_url => '/',
        :verb => "GETTY")
      headers.each{|k,v| header(k,v)}
      get '/'
      last_response.status.should == 401
    end
    
    it "should return 401 if client's app_uuid is unknown to MAuth" do
      headers = MAuth::Signer.new(:private_key => PRIVATE_KEY).signed_request_headers(
        :app_uuid => "appuuid_does_not_exist123",
        :request_url => '/',
        :verb => "GET")
      headers.each{ |k,v| header(k,v) }
      get '/'
      last_response.status.should == 401
    end
    
  end
  
  describe "MAuth is down" do
    before(:each) do
      class Medidata::MAuthMiddleware
        attr_reader :mauth_verifiers_manager
      end
    end
    
    it "should return 401 if MAuth is not responding and public key for app hasn't already been cached by rack-mauth" do
      RestClient::Resource.stub_chain(:new, :get).and_raise(Errno::ECONNREFUSED.new)
      headers = MAuth::Signer.new(:private_key => PRIVATE_KEY).signed_request_headers(
        :app_uuid => APP_UUID,
        :request_url => '/',
        :verb => "GET")
      headers.each{ |k,v| header(k,v) }
      get '/'
      last_response.status.should == 401
    end
    
    it "should return 200 if MAuth is not responding but public key for app has already been cached by rack-mauth" do
      headers = MAuth::Signer.new(:private_key => PRIVATE_KEY).signed_request_headers(
        :app_uuid => APP_UUID,
        :request_url => '/',
        :verb => "GET")
      headers.each{ |k,v| header(k,v) }
      get '/'
      RestClient::Resource.stub_chain(:new, :get).and_raise(Errno::ECONNREFUSED.new)
      headers.each{ |k,v| header(k,v) }
      get '/'
      last_response.status.should == 200
    end
    
  end
  
end