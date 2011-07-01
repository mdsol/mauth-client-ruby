$: << 'lib'
require 'mauth_signer'

@app_uuid = "11111111-1111-1111-1111-111111111111"
@private_key = %{-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCr7rJOrG5DN+dWZMNlNcuQxUjhRfQUWQuqM9sWXpNDl7QYEfVE
eJBnFIMXfennRaoPdJY9JzkNaf+tMd2WmdRS5OLKlfdY/6bNE2MAjUIspG6comcL
nlLRE7IPa9kg690XRFkgyn31JI2hmjGFVuH5Rpvj4HJkT/cBQUykVsPtUQIDAQAB
AoGBAIcAkrn740icqOXJkTPznbg7cRKSXylrEiG/PhS+hlvYzuznjPMKyDhoftb/
Y57ZsMMaBK5YEhBaXwybzybl+zUhjRB6ShuWmuI50m9bZNScb3iQL3Ao7WoZcFgk
YB6Dj7K3XioF4XT9h75VrA5fVmGX52LfSjS37RdDraDHs5bRAkEA4LIMWdjaeaKj
Sb7L6dioh+6Pmfe8UPKdHcYGU5jV6OfGt8mimjsw+d69RQpFRYMPA7Uum6lLimrN
5I0u944LswJBAMPizwhjjdyvDSExisB7zZyb9tPSbLshbTcyxLfmLRrivNLrOFzl
kLF0glLA6OTA6axC4tgIS7jnH3q7LYzMEOsCQAFf9YVjN0sBPMCJw1Ol+LoEMqq9
glB4e4+gE4/VYpGvQV8Eg9Mvw4fz3fKbMntPZvsd07AuJAEv0Byy5HOtUdMCQGwP
4VqlYQtPXpTjOcI6ChHNUHtGaElLhW6gCTnSNyvPzY8lyDAnTI040vRIC7K2YbJw
K6g122Aj0I/qVpSHtwUCQQCdyA0qpTTeueUgOGNeid7SNhbLHQfAe7BiCvWwLuL2
vaFezysB0FeSHl6dmwWXE6peRjhueMX1CseHOnj6FITP
-----END RSA PRIVATE KEY-----
}


def simple_request(host, url, post_data)
  headers = MAuth::Signer.new(@private_key).signed_headers(:app_uuid => @app_uuid, :request_url => url, :post_data => post_data, :verb => 'POST')
  puts "HEADERS: #{headers.inspect}"

  args = headers.map{|k,v| "-H '#{k}: #{v}'"} * ' '
  "curl -v #{args} -d '#{post_data}' #{host}#{url}"
end


puts simple_request('http://localhost:3000', '/studies', 'foo=bar')
puts simple_request('http://localhost:3001', '/studies', 'foo=bar')


