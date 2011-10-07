$: << 'lib'
require 'mauth_signer'

@app_uuid = "11111111-1111-1111-1111-111111111111"
@private_key = "VWuEoMS66BuANIUvyn7yAUwR5Oz8J1FOrXBSNB28MDDHqiPuiLCu2jrQlA5jYW509/ncs6j2K8GdkSzqJIqOTg=="

def simple_request(host, url, post_data)
  headers = MAuth::Signer.new(@private_key).signed_headers(:app_uuid => @app_uuid, :request_url => url, :post_data => post_data, :verb => 'POST')
  puts "HEADERS: #{headers.inspect}"

  args = headers.map{|k,v| "-H '#{k}: #{v}'"} * ' '
  "curl -v #{args} -d '#{post_data}' #{host}#{url}"
end

puts simple_request('http://localhost:3000', '/studies', 'foo=bar')
puts simple_request('http://localhost:3001', '/studies', 'foo=bar')


