shared_context 'client' do
  let(:app_uuid) { 'signer' }
  let(:request) { TestSignableRequest.new(verb: 'PUT', request_url: '/', body: 'himom') }
  let(:v2_only_sign_requests) { false }
  let(:v1_only_sign_requests) { false }
  let(:v2_only_authenticate) { false }
  let(:disable_fallback_to_v1_on_v2_failure) { false }
  let(:v1_signed_req) { client.signed_v1(request) }
  let(:v2_signed_req) { client.signed_v2(request) }
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:client) do
    Mauth::Client.new(
      private_key: signing_key,
      app_uuid: app_uuid,
      v2_only_sign_requests: v2_only_sign_requests,
      v2_only_authenticate: v2_only_authenticate,
      v1_only_sign_requests: v1_only_sign_requests,
      disable_fallback_to_v1_on_v2_failure: disable_fallback_to_v1_on_v2_failure
    )
  end

  require 'mauth/request_and_response'
  class TestSignableRequest < Mauth::Request
    include Mauth::Signed
    attr_accessor :headers

    def merge_headers(headers)
      self.class.new(@attributes_for_signing).tap{ |r| r.headers = (@headers || {}).merge(headers) }
    end

    def x_mws_time
      headers['X-MWS-Time']
    end

    def x_mws_authentication
      headers['X-MWS-Authentication']
    end

    def mcc_authentication
      headers['MCC-Authentication']
    end

    def mcc_time
      headers['MCC-Time']
    end
  end
end
