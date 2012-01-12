$: << 'lib'
require 'mauth_signer'
require 'openssl'

@private_key = OpenSSL::PKey::RSA.generate( 2048 )
@private_key_str = @private_key.to_s
@public_key_str = @private_key.public_key.to_s
@app_uuid = "11111111-1111-1111-1111-111111111111"

def generate_signed_request(params)
  MAuth::Signer.new(:private_key => @private_key_str).signed_request_headers(params)
end

def verify_request(signature, params)
  MAuth::Signer.new(:public_key => @public_key_str).verify_request(signature, params)
end

def generate_signed_response(params)
  MAuth::Signer.new(:private_key => @private_key_str).signed_response_headers(params)
end

def verify_response(signature, params)
  MAuth::Signer.new(:public_key => @public_key_str).verify_response(signature, params)
end

params = {:app_uuid => @app_uuid, :request_url => '/studies', :body => 'hello=there', :verb => 'PUT'}
headers = generate_signed_request(params)
sig_time = headers["x-mws-time"]
sig = headers["Authorization"].split(':').last
puts verify_request(sig, params.merge(:time => sig_time))

params = {:app_uuid => @app_uuid, :body => 'hello=there', :status_code => 404}
headers = generate_signed_response(params)
sig_time = headers["x-mws-time"]
sig = headers["x-mws-authentication"].split(':').last
puts verify_response(sig, params.merge(:time => sig_time))

