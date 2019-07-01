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

end
