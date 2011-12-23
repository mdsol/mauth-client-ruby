require 'rubygems'
require 'bundler/setup'
require 'mauth_signer'

@app_uuid = "YOUR APP UUID HERE"

@private_key = "YOUR PRIVATE KEY HERE"

def generate_url (url)
 "#{url}#{@app_uuid}.json"
end

def simple_request(host, url, verb='GET', post_data=nil)
  headers = MAuth::Signer.new(@private_key).signed_headers(:app_uuid => @app_uuid, :request_url => generate_url(url), :post_data => post_data, :verb => verb)
  puts "HEADERS: #{headers.inspect}"

  args = headers.map{|k,v| "-H '#{k}: #{v}'"} * ' '
  if post_data == nil
  "curl -v #{args} #{host}#{generate_url(url)}"
  else
  "curl -v #{args} -d '#{post_data}' #{host}#{generate_url(url)}"
  end
end

#puts simple_request('https://mauth-sandbox.imedidata.net', '/mauth/v1/security_tokens/')
#puts simple_request('http://localhost:3000', '/mauth/v1/security_tokens/')
#puts simple_request('http://localhost:4004', '/mauth/v1/security_tokens/', 'POST', 'foo=bar')
puts simple_request('http://localhost:3000', '/api/studies/1/subjects/1', 'POST', 'foo=bar')
