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

  describe 'cross platform signature testing' do
    let(:testing_info) { JSON.parse(IO.read('spec/fixtures/mauth_signature_testing.json'), symbolize_names: true) }
    let(:client) do
      MAuth::Client.new(
        private_key: testing_info[:private_key],
        app_uuid: testing_info[:app_uuid]
      )
    end

    let(:request) { MAuth::Request.new(attributes_for_signing) }
    let(:attributes_for_signing) do
      testing_info[:attributes_for_signing].tap do |attributes|
        attributes[:body] = body
      end
    end

    describe 'binary body' do
      let(:body) { File.binread('spec/fixtures/blank.jpeg') }

      it 'returns accurate v1 signature' do
        signature_v1 = client.signature_v1(request.string_to_sign_v1({}))
        expect(signature_v1).to eq(testing_info[:signatures][:v1_binary])
      end

      it 'returns accurate v2 signature' do
        signature_v2 = client.signature_v2(request.string_to_sign_v2({}))
        expect(signature_v2).to eq(testing_info[:signatures][:v2_binary])
      end
    end

    describe 'empty body' do
      let(:body) { '' }

      it 'returns accurate v1 signature' do
        signature_v1 = client.signature_v1(request.string_to_sign_v1({}))
        expect(signature_v1).to eq(testing_info[:signatures][:v1_empty])
      end

      it 'returns accurate v2 signature' do
        signature_v2 = client.signature_v2(request.string_to_sign_v2({}))
        expect(signature_v2).to eq(testing_info[:signatures][:v2_empty])
      end
    end
  end
end
