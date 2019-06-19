require 'spec_helper'
require 'mauth/request_and_response'
require 'mauth/client'
require 'byebug'

describe MAuth::Signable do
  let(:more_attrs) { { time: Time.now, app_uuid: 'signer' } }
  let(:resp_attrs) { { status_code: 200, body: '{"k": "v"}' }.merge(more_attrs) }
  let(:req_attrs) do
    { verb: 'PUT', request_url: '/', body: '{}', query_string: 'k=v' }
      .merge(more_attrs)
  end
  let(:dummy_cls) do
    class Dummy
      include MAuth::Signable
    end
    Dummy.const_set(const_name, sig_components)
    Dummy
  end


  describe 'string_to_sign_v1({})' do
    let(:const_name) { 'SIGNATURE_COMPONENTS' }

    context 'requests' do
      let(:sig_components) { %i[verb request_url body app_uuid time] }

      %i[verb request_url app_uuid time].each do |component|
        it "raises when the signature component `#{component}` is missing" do
          req_attrs.delete(component)
          dummy_inst = dummy_cls.new(req_attrs)
          expect { dummy_inst.string_to_sign_v1({}) }
            .to raise_error(MAuth::UnableToSignError)
        end
      end

      it 'does not raise when `body` is missing' do
        req_attrs.delete(:body)
        dummy_inst = dummy_cls.new(req_attrs)
        expect { dummy_inst.string_to_sign_v1({}) }.not_to raise_error
      end
    end

    context 'responses' do
      let(:sig_components) { %i[status_code body app_uuid time] }

      %i[status_code app_uuid time].each do |component|
        it "raises when the signature component `#{component}` is missing" do
          resp_attrs.delete(component)
          dummy_inst = dummy_cls.new(resp_attrs)
          expect { dummy_inst.string_to_sign_v1({}) }
            .to raise_error(MAuth::UnableToSignError)
        end
      end

      it 'does not raise when `body` is missing' do
        resp_attrs.delete(:body)
        dummy_inst = dummy_cls.new(resp_attrs)
        expect { dummy_inst.string_to_sign_v1({}) }.not_to raise_error
      end
    end
  end

  describe 'string_to_sign_v2' do
    let(:const_name) { 'SIGNATURE_COMPONENTS_V2'}

    context 'requests' do
      let(:sig_components) do
        %i[verb request_url body_digest app_uuid time encoded_query_params]
      end

      %i[verb request_url app_uuid time].each do |component|
        it "raises when the signature component `#{component}` is missing" do
          req_attrs.delete(component)
          dummy_inst = dummy_cls.new(req_attrs)
          expect { dummy_inst.string_to_sign_v2({}) }
            .to raise_error(MAuth::UnableToSignError)
        end
      end

      %i[body_digest encoded_query_params].each do |component|
        it "does not raise when the signature component `#{component}` is missing" do
          req_attrs.delete(component)
          dummy_inst = dummy_cls.new(req_attrs)
          expect { dummy_inst.string_to_sign_v2({}) }.not_to raise_error
        end
      end

      it 'hashes the request body with SHA512' do
        expect(Digest::SHA512).to receive(:hexdigest).with(req_attrs[:body]).once
        # this spec fails unless we expect Digest::SHA512 to be called again
        # with the concatenated signature components
        expect(Digest::SHA512).to receive(:hexdigest).with(anything)
        dummy_inst = dummy_cls.new(req_attrs)
        dummy_inst.string_to_sign_v2({})
      end

      xit 'enforces UTF-8 encoding for all components of the string to sign' do
        dummy_inst = dummy_cls.new(req_attrs)
        dummy_inst.string_to_sign_v2({}).split("\n\r").each do |component|
          expect(component.encoding.to_s).to eq('UTF-8')
        end
      end
    end

    context 'responses' do
      let(:sig_components) { %i[status_code body_digest app_uuid time] }

      %i[status_code app_uuid time].each do |component|
        it "raises when the signature component `#{component}` is missing" do
          resp_attrs.delete(component)
          dummy_inst = dummy_cls.new(resp_attrs)
          expect { dummy_inst.string_to_sign_v2({}) }
            .to raise_error(MAuth::UnableToSignError)
        end
      end

      it 'does not raise when `body_digest` is missing' do
        resp_attrs.delete(:body_digest)
        dummy_inst = dummy_cls.new(resp_attrs)
        expect { dummy_inst.string_to_sign_v2({}) }.not_to raise_error
      end

      it 'hashes the request body with SHA512' do
        expect(Digest::SHA512).to receive(:hexdigest).with(resp_attrs[:body]).once
        # this spec fails unless we expect Digest::SHA512 to be called again
        # with the concatenated signature components
        expect(Digest::SHA512).to receive(:hexdigest).with(anything)
        dummy_inst = dummy_cls.new(resp_attrs)
        dummy_inst.string_to_sign_v2({})
      end
    end
  end

  describe 'encode_query_string' do
    let(:dummy_inst) { Class.new { include MAuth::Signable }.new({}) }

    it 'uri encodes special characters in keys and values of the parameters' do
      qs = "key=-_.~!@#$%^*()+{}|:\"'`<>?"
      expected = 'key=-_.~%21%40%23%24%25%5E%2A%28%29%2B%7B%7D%7C%3A%22%27%60%3C%3E%3F'
      expect(dummy_inst.encode_query_string(qs)).to eq(expected)
    end

    it 'sorts query parameters by code point in ascending order' do
      qs = '∞=v&キ=v&0=v&a=v'
      expected = '0=v&a=v&%E2%88%9E=v&%E3%82%AD=v'
      expect(dummy_inst.encode_query_string(qs)).to eq(expected)
    end

    it 'sorts query parameters by value if keys are the same' do
      qs = 'a=b&a=c&a=a'
      expected = 'a=a&a=b&a=c'
      expect(dummy_inst.encode_query_string(qs)).to eq(expected)
    end

    it 'properly handles query strings with empty values' do
      qs = 'k=&k=v'
      expect(dummy_inst.encode_query_string(qs)).to eq(qs)
    end

    it 'properly handles empty strings' do
      expect(dummy_inst.encode_query_string('')).to eq('')
    end
  end
end
