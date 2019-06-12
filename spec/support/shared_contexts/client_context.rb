shared_context 'client' do
  let(:app_uuid) { 'signer' }
  let(:request) { TestSignableRequest.new(verb: 'PUT', request_url: '/', body: 'himom') }
  let(:sign_requests_with_only_v2) { false }
  let(:authenticate_with_only_v2) { false }
  let(:v1_signed_req) { client.signed(request, v1_only_override: true) }
  let(:v2_signed_req) { client.signed(request, v2_only_override: true) }
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:client) do
    MAuth::Client.new(
      private_key: signing_key,
      app_uuid: app_uuid,
      sign_requests_with_only_v2: sign_requests_with_only_v2,
      authenticate_with_only_v2: authenticate_with_only_v2
    )
  end
end
