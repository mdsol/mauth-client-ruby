require 'rubygems'
require 'bundler/setup'
require 'mauth_signer'

@app_uuid = "91111111-1111-1111-1111-111111111111"
@private_key = "QpeIisdvU9AJC15wkLf83xDPiCFaTL6r8iQY56nZqaqp0yTfJVKAgtOqdGyAOyVDd9b2Uz8ZukiyXR5H56JLEg=="
#@app_uuid = "YOUR APP UUID HERE"

#@private_key = "YOUR PRIVATE KEY HERE"

def generate_url
  "#{@host}#{@url}"
end

def simple_request(host, url, verb='GET', post_data='')
  @host, @url = host, url
  headers = MAuth::Signer.new(@private_key).signed_headers(:app_uuid => @app_uuid, :request_url => @url, :post_data => post_data, :verb => verb)
  puts "HEADERS: #{headers.inspect}"
  puts @private_key
  puts host
  puts url
  puts @app_uuid
  puts verb

  args = headers.map{|k,v| "-H '#{k}: #{v}'"} * ' '
  if post_data == ''
  "curl -v #{args} #{generate_url}"
  else
  "curl -v #{args} -d '#{post_data}' #{generate_url}"
  end
end

#puts simple_request('https://mauth-sandbox.imedidata.net', '/mauth/v1/security_tokens/')
#puts simple_request('http://localhost:3000', '/mauth/v1/security_tokens/')
#puts simple_request('http://localhost:4004', '/mauth/v1/security_tokens/', 'POST', 'foo=bar')
puts simple_request('http://localhost:9292', '/')
