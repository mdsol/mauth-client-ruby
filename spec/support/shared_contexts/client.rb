# frozen_string_literal: true

require "support/shared_contexts/test_signable_request"

shared_context "client" do
  include_context "with TestSignableRequest"

  let(:app_uuid) { "signer" }
  let(:request) { TestSignableRequest.new(verb: "PUT", request_url: "/", body: "himom") }
  let(:v2_only_sign_requests) { false }
  let(:v1_only_sign_requests) { false }
  let(:v2_only_authenticate) { false }
  let(:disable_fallback_to_v1_on_v2_failure) { false }
  let(:v1_signed_req) { client.signed_v1(request) }
  let(:v2_signed_req) { client.signed_v2(request) }
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:client) do
    MAuth::Client.new(
      private_key: signing_key,
      app_uuid: app_uuid,
      v2_only_sign_requests: v2_only_sign_requests,
      v2_only_authenticate: v2_only_authenticate,
      v1_only_sign_requests: v1_only_sign_requests,
      disable_fallback_to_v1_on_v2_failure: disable_fallback_to_v1_on_v2_failure
    )
  end
end
