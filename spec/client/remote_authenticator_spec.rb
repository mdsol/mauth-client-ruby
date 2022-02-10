# frozen_string_literal: true

require "spec_helper"
require "faraday"
require "mauth/client"
require_relative "../support/shared_contexts/client"
require_relative "../support/shared_examples/authenticator_base"

describe MAuth::Client::RemoteRequestAuthenticator do
  include_context "client"

  let(:authenticating_mc) do
    MAuth::Client.new(
      mauth_baseurl: "http://whatever",
      mauth_api_version: "v1",
      app_uuid: "authenticator",
      v2_only_authenticate: v2_only_authenticate,
      disable_fallback_to_v1_on_v2_failure: disable_fallback_to_v1_on_v2_failure
    )
  end

  describe "#authentic?" do
    let(:stubs) { Faraday::Adapter::Test::Stubs.new }
    let(:test_faraday) do
      ::Faraday.new do |builder|
        builder.adapter(:test, stubs)
      end
    end
    let(:query_string) { "key=value&coolkey=coolvalue" }
    let(:qs_request) do
      TestSignableRequest.new(
        verb: "PUT",
        request_url: "/",
        body: "himom",
        query_string: query_string
      )
    end

    before do
      expect(authenticating_mc).to be_kind_of(MAuth::Client::RemoteRequestAuthenticator)
      stubs.post("/mauth/v1/authentication_tickets.json") { [204, {}, []] }
      allow(::Faraday).to receive(:new).and_return(test_faraday)
    end

    include_examples MAuth::Client::AuthenticatorBase

    it "considers a request to be authentic if mauth reports it so" do
      signed_request = client.signed(request)
      expect(authenticating_mc.authentic?(signed_request)).to be true
    end

    it "considers a request to be inauthentic if mauth reports it so" do
      stubs.instance_eval { @stack.clear } # HAX
      stubs.post("/mauth/v1/authentication_tickets.json") { [412, {}, []] }
      signed_request = client.signed(request)
      expect(authenticating_mc.authentic?(signed_request)).to be_falsey
    end

    context "when authenticating with v2" do
      it "includes the query string and token in the request" do
        expect(test_faraday).to receive(:post).with(
          "/mauth/v1/authentication_tickets.json",
          /\A\{"authentication_ticket":.*"query_string":"#{query_string}","token":"MWSV2"\}\}\z/
        ).and_return(double("resp", status: 200))

        signed_request = client.signed(qs_request)
        authenticating_mc.authentic?(signed_request)
      end
    end
  end

  describe "#make_mauth_request" do
    let(:authentication_ticket) do
      {
        verb: "PUT",
        app_uuid: "signer",
        client_signature: "YIhI4uW1ebAjOyNsFcqDbtKg4NUxul==",
        request_url: "/",
        request_time: "1644382800",
        b64encoded_body: "aGltb20=\n",
        query_string: nil,
        token: "MWSV2"
      }
    end

    let(:mauth_url) { "http://whatever/mauth/v1/authentication_tickets.json" }

    before do
      stub_request(:post, mauth_url).to_return(status: 204)
    end

    it "encodes body" do
      authenticating_mc.send(:make_mauth_request, authentication_ticket)
      expect(WebMock).to have_requested(:post, mauth_url)
        .with(
          body: JSON.generate(authentication_ticket: authentication_ticket),
          headers: { "Content-Type" => "application/json" }
        )
    end
  end
end
