require 'spec_helper'
require 'mauth/client'
require_relative '../support/shared_contexts/client.rb'


describe MAuth::Client::Signer do
  include_context 'client'

  describe '#signed' do
    context 'when the v2_only_sign_requests flag is true' do
      let(:v2_only_sign_requests) { true }

      it 'adds only MCC-Time and MCC-Authentication headers when signing' do
        signed_request = client.signed(request)
        expect(signed_request.headers.keys).to include('MCC-Authentication', 'MCC-Time')
        expect(signed_request.headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
      end
    end

    it 'by default adds X-MWS-Time, X-MWS-Authentication, MCC-Time, MCC-Authentication headers when signing' do
      signed_request = client.signed(request)
      expect(signed_request.headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time','MCC-Authentication', 'MCC-Time')
    end

    it "can't sign without a private key" do
      mc = MAuth::Client.new(app_uuid: app_uuid)
      expect { mc.signed(request) }.to raise_error(MAuth::UnableToSignError)
    end

    it "can't sign without an app uuid" do
      mc = MAuth::Client.new(private_key: OpenSSL::PKey::RSA.generate(2048))
      expect { mc.signed(request) }.to raise_error(MAuth::UnableToSignError)
    end
  end

  describe '#signed_v1' do
    it 'adds only X-MWS-Time and X-MWS-Authentication headers' do
      expect(v1_signed_req.headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time')
      expect(v1_signed_req.headers.keys).not_to include('MCC-Authentication', 'MCC-Time')
    end
  end

  describe '#signed_v2' do
    it 'adds only MCC-Time and MCC-Authentication headers' do
      expect(v2_signed_req.headers.keys).to include('MCC-Authentication', 'MCC-Time')
      expect(v2_signed_req.headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
    end
  end

  describe '#signed_headers' do
    context 'when the v2_only_sign_requests flag is true' do
      let(:v2_only_sign_requests) { true }

      it 'returns only MCC-Time and MCC-Authentication headers when signing' do
        signed_headers = client.signed_headers(request)
        expect(signed_headers.keys).to include('MCC-Authentication', 'MCC-Time')
        expect(signed_headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
      end
    end

    it 'by default returns X-MWS-Time, X-MWS-Authentication, MCC-Time, MCC-Authentication headers' do
      signed_headers = client.signed_headers(request)
      expect(signed_headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time', 'MCC-Authentication', 'MCC-Time')
    end
  end

  describe '#signed_headers_v1' do
    it 'returns only X-MWS-Time and X-MWS-Authentication headers' do
      signed_headers = client.signed_headers_v1(request)
      expect(signed_headers.keys).to include('X-MWS-Authentication', 'X-MWS-Time')
      expect(signed_headers.keys).not_to include('MCC-Authentication', 'MCC-Time')
    end
  end

  describe '#signed_headers_v2' do
    it 'returns only MCC-Time and MCC-Authentication headers' do
      signed_headers = client.signed_headers_v2(request)
      expect(signed_headers.keys).to include('MCC-Authentication', 'MCC-Time')
      expect(signed_headers.keys).not_to include('X-MWS-Authentication', 'X-MWS-Time')
    end
  end

  describe 'signature methods' do
    let(:string_to_sign) { 'dummy str' }
    let(:mock_pkey) { double('private_key', sign: 'encoded_message', private_encrypt: 'encoded') }

    before do
      allow(client).to receive(:private_key).and_return(mock_pkey)
    end

    describe '#signature_v1' do
      it 'base 64 encodes the signed digest' do
        signature = client.signature_v1(string_to_sign)
        expect(Base64.decode64(signature)).to eq('encoded')
      end

      it 'handles newlines appropriately' do
        signature = client.signature_v1(string_to_sign)
        expect(signature !~ /\n/).to be(true)
      end
    end

    describe '#signature_v2' do
      it 'base 64 encodes the signed digest' do
        signature = client.signature_v2(string_to_sign)
        expect(Base64.decode64(signature)).to eq('encoded_message')
      end

      it 'handles newlines appropriately' do
        signature = client.signature_v2(string_to_sign)
        expect(signature !~ /\n/).to be(true)
      end

      it 'calls `sign` with an OpenSSL SHA512 digest' do
        expect(mock_pkey).to receive(:sign)
          .with(an_instance_of(OpenSSL::Digest::SHA512), string_to_sign)
        client.signature_v2(string_to_sign)
      end
    end
  end

  describe 'cross platform signature value check' do
    let(:client) do
      MAuth::Client.new(
        private_key_file: 'spec/fixtures/fake.key',
        app_uuid: app_uuid
      )
    end

    let(:binary_file_body) { File.binread('spec/fixtures/blank.jpeg') }

    let(:attributes_for_signing) do
      {
        app_uuid: '5ff4257e-9c16-11e0-b048-0026bbfffe5e',
        time: 1309891855, # 2011-07-05 18:50:00 UTC
        verb: 'PUT',
        request_url: '/v1/pictures',
        body: binary_file_body,
        query_string: "key=-_.~!@#$%^*()+{}|:\"'`<>?&∞=v&キ=v&0=v&a=v&a=b&a=c&a=a&k=&k=v"
      }
    end

    let(:request) { MAuth::Request.new(attributes_for_signing) }

    it 'returns accurate v1 signature' do
      signature_v1 = client.signature_v1(request.string_to_sign_v1({}))
      expect(signature_v1).to eq(
        "hDKYDRnzPFL2gzsru4zn7c7E7KpEvexeF4F5IR+puDxYXrMmuT2/fETZty5NkGGTZQ1nI6BTYGQGsU/73TkEAm7SvbJZcB2duLSCn8H5D0S1cafory1gnL1TpMPBlY8J/lq/Mht2E17eYw+P87FcpvDShINzy8GxWHqfquBqO8ml4XtirVEtAlI0xlkAsKkVq4nj7rKZUMS85mzogjUAJn3WgpGCNXVU+EK+qElW5QXk3I9uozByZhwBcYt5Cnlg15o99+53wKzMMmdvFmVjA1DeUaSO7LMIuw4ZNLVdDcHJx7ZSpAKZ/EA34u1fYNECFcw5CSKOjdlU7JFr4o8Phw=="
      )
    end

    it 'returns accurate v2 signature' do
      signature_v2 = client.signature_v2(request.string_to_sign_v2({}))
      expect(signature_v2).to eq(
        "kXMtivUVa2aciWcHpxWNFtIAKGHkbC2LjvQCYx5llhhiZOfFQOWNyEcy3qdHj03g27FhefGeMNke/4PThXVRD0fg06Kn+wSCZp+ZHTxUp9m1ZDjlAaNGYjS+LMkQs2oxwg/iJFFAAzvjxzZ9jIhinWM6+PXok5NfU2rvbjjaI5WfRZa8wNl0NeOYlBZPICTcARbT1G6Kr3bjkgBTixNY2dSR1s7MmvpPHzfWSAyaYFppWnJwstRAU/JsR/JzcATZNx/CIk8N+46aWN1Na5avQgLFoNJn6eenXW3W51cENQyhtw7jatvrIKnVckAMoOkygfkbHdCixNfV5G0u1LHU3w=="
      )
    end
  end
end
