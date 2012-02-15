$: << 'lib'
require 'mauth-client'
require 'openssl'
require 'uuidtools'
require 'mauth/request_and_response'

private_key = OpenSSL::PKey::RSA.generate(2048)
app_uuid = UUIDTools::UUID.random_create.to_s

mauth_client = MAuth::Client.new(:private_key => private_key, :app_uuid => app_uuid)

params = {:app_uuid => app_uuid, :request_url => '/studies', :body => 'hello=there', :verb => 'PUT'}
request = MAuth::Request.new(params)
headers = mauth_client.signed_headers(request)
sig_time = headers["X-MWS-Time"]
sig = headers["X-MWS-Authentication"].split(':').last

params = {:app_uuid => app_uuid, :body => 'hello=there', :status_code => 404}
response = MAuth::Response.new(params)
headers = mauth_client.signed_headers(response)
sig_time = headers["X-MWS-Time"]
sig = headers["X-MWS-Authentication"].split(':').last
