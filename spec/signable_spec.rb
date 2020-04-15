require 'spec_helper'
require 'mauth/request_and_response'
require 'mauth/client'

describe MAuth::Signable do
  let(:more_attrs) { { time: Time.now, app_uuid: 'signer' } }
  let(:resp_attrs) { { status_code: 200, body: '{"k": "v"}' }.merge(more_attrs) }
  let(:req_attrs) do
    { verb: 'PUT', request_url: '/', body: '{}', query_string: 'k=v' }
      .merge(more_attrs)
  end
  let(:frozen_req_attrs) { req_attrs.each_with_object({}) { |(k, v), h| h[k] = v.is_a?(String) ? v.freeze : v } }
  let(:dummy_cls) do
    class Dummy
      include MAuth::Signable
    end
    Dummy.send(:remove_const, const_name) if Dummy.const_defined?(const_name)
    Dummy.const_set(const_name, sig_components)
    Dummy
  end
  let(:dummy_inst) { Class.new { include MAuth::Signable }.new({}) }


  describe 'string_to_sign_v1' do
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
          dummy_req = dummy_cls.new(req_attrs)
          expect { dummy_req.string_to_sign_v2({}) }
            .to raise_error(MAuth::UnableToSignError)
        end
      end

      %i[body_digest encoded_query_params].each do |component|
        it "does not raise when the signature component `#{component}` is missing" do
          req_attrs.delete(component)
          dummy_req = dummy_cls.new(req_attrs)
          expect { dummy_req.string_to_sign_v2({}) }.not_to raise_error
        end
      end

      it 'hashes the request body with SHA512' do
        expect(Digest::SHA512).to receive(:hexdigest).with(req_attrs[:body]).once
        dummy_req = dummy_cls.new(req_attrs)
        dummy_req.string_to_sign_v2({})
      end

      it 'enforces UTF-8 encoding for all components of the string to sign' do
        dummy_req = dummy_cls.new(req_attrs)
        str = dummy_req.string_to_sign_v2({})

        str.split("\n\r").each do |component|
          expect(component.encoding.to_s).to eq('UTF-8')
        end
      end

      it 'does not raise when all string components of the string to sign are frozen' do
        dummy_req = dummy_cls.new(frozen_req_attrs)
        expect { dummy_req.string_to_sign_v2({}) }.not_to raise_error
      end

      # we have this spec because Faraday and Rack handle empty request bodies
      # differently.
      # our Rack::Request class reads the body of a bodiless-request as an empty string
      # our Faraday::Request class reads the body of a bodiless-request as nil
      it 'treats requests where the body is nil and the body is an empty request the same' do
        nil_body_attrs = req_attrs.merge(body: nil)
        empty_body_attrs = req_attrs.merge(body: '')

        nil_req = dummy_cls.new(nil_body_attrs)
        empy_req = dummy_cls.new(empty_body_attrs)

        expect(nil_req.string_to_sign_v2({})).to eq(empy_req.string_to_sign_v2({}))
      end
    end

    context 'responses' do
      let(:sig_components) { %i[status_code body_digest app_uuid time] }

      %i[status_code app_uuid time].each do |component|
        it "raises when the signature component `#{component}` is missing" do
          resp_attrs.delete(component)
          dummy_resp = dummy_cls.new(resp_attrs)
          expect { dummy_resp.string_to_sign_v2({}) }
            .to raise_error(MAuth::UnableToSignError)
        end
      end

      it 'does not raise when `body_digest` is missing' do
        resp_attrs.delete(:body_digest)
        dummy_resp = dummy_cls.new(resp_attrs)
        expect { dummy_resp.string_to_sign_v2({}) }.not_to raise_error
      end

      it 'hashes the response body with SHA512' do
        expect(Digest::SHA512).to receive(:hexdigest).with(resp_attrs[:body]).once
        dummy_req = dummy_cls.new(resp_attrs)
        dummy_req.string_to_sign_v2({})
      end

      it 'enforces UTF-8 encoding for all components of the string to sign' do
        dummy_req = dummy_cls.new(resp_attrs)
        str = dummy_req.string_to_sign_v2({})

        str.split("\n\r").each do |component|
          expect(component.encoding.to_s).to eq('UTF-8')
        end
      end
    end
  end

  describe 'unescape_encode_query_string' do
    it 'uri encodes special characters in keys and values of the parameters' do
      qs = "key=-_.~!@#$%^*(){}|:\"'`<>?"
      expected = 'key=-_.~%21%40%23%24%25%5E%2A%28%29%7B%7D%7C%3A%22%27%60%3C%3E%3F'
      expect(dummy_inst.unescape_encode_query_string(qs)).to eq(expected)
    end

    it 'sorts query parameters by code point in ascending order' do
      qs = '∞=v&キ=v&0=v&a=v'
      expected = '0=v&a=v&%E2%88%9E=v&%E3%82%AD=v'
      expect(dummy_inst.unescape_encode_query_string(qs)).to eq(expected)
    end

    it 'sorts query parameters by value if keys are the same' do
      qs = 'a=b&a=c&a=a'
      expected = 'a=a&a=b&a=c'
      expect(dummy_inst.unescape_encode_query_string(qs)).to eq(expected)
    end

    it 'properly handles query strings with empty values' do
      qs = 'k=&k=v'
      expect(dummy_inst.unescape_encode_query_string(qs)).to eq(qs)
    end

    it 'properly handles empty strings' do
      expect(dummy_inst.unescape_encode_query_string('')).to eq('')
    end

    it 'unescapes special characters in the query string before encoding them' do
      qs = 'key=-_.%21%40%23%24%25%5E%2A%28%29%20%7B%7D%7C%3A%22%27%60%3C%3E%3F'
      expected = 'key=-_.%21%40%23%24%25%5E%2A%28%29%20%7B%7D%7C%3A%22%27%60%3C%3E%3F'
      expect(dummy_inst.unescape_encode_query_string(qs)).to eq(expected)
    end

    it 'unescapes "%7E" to "~"' do
      qs = 'k=%7E'
      expected = 'k=~'
      expect(dummy_inst.unescape_encode_query_string(qs)).to eq(expected)
    end

    it 'unescapes "+" to " "' do
      qs = 'k=+'
      expected = 'k=%20'
      expect(dummy_inst.unescape_encode_query_string(qs)).to eq(expected)
    end

    it 'sorts after unescaping' do
      qs = 'k=%7E&k=~&k=%40&k=a'
      expected = 'k=%40&k=a&k=~&k=~'
      expect(dummy_inst.unescape_encode_query_string(qs)).to eq(expected)
    end
  end

  describe 'uri_escape' do
    it 'uri encodes special characters' do
      str = "!@#$%^*()+{}|:\"'`<>?"
      expected = '%21%40%23%24%25%5E%2A%28%29%2B%7B%7D%7C%3A%22%27%60%3C%3E%3F'
      expect(dummy_inst.uri_escape(str)).to eq(expected)
    end

    %w[~ _ . - a A 0].each do |char|
      it "does not uri encode `#{char}`" do
        expect(dummy_inst.uri_escape(char)).to eq(char)
      end
    end

    it 'encodes space as %20' do
      expect(dummy_inst.uri_escape(' ')).to eq('%20')
    end
  end

  describe 'normalize_path' do
    # normalizes percent encoding to uppercase i.e. %cf%80 => %CF%80
    # normalizes `.` and `..` in path i.e. /./example => /example ; /example/.. => /
    # must add String#squeeze to remove duplicated slahes i.e. /// => /
    # Addressable::URI.parse(path).normalize.to_s.squeeze('/')

    it 'normalizes self (".") in the path' do
      path = '/./example/./.'
      expected = '/example/'
      expect(dummy_inst.normalize_path(path)).to eq(expected)
    end

    it 'normalizes parent ("..") in path' do
      path = '/example/sample/..'
      expected = '/example/'
      expect(dummy_inst.normalize_path(path)).to eq(expected)
    end

    it 'normalizes parent ("..") that points to non-existent parent' do
      path = '/example/sample/../../../..'
      expected = '/'
      expect(dummy_inst.normalize_path(path)).to eq(expected)
    end

    it 'normalizes case of percent encoded characters' do
      path = '/%2b'
      # path = '%cf%80'
      # path = '%7e'
      expected = '/%2B'
      # expected = '%CF%80'
      # expected = '%7E'
      expect(dummy_inst.normalize_path(path)).to eq(expected)
    end

    it 'normalizs multiple adjacent slashes to a single slash' do
      path = '//example///sample'
      expected = '/example/sample'
      expect(dummy_inst.normalize_path(path)).to eq(expected)
    end

    it 'preserves trailing slashes' do
      path = '/example/'
      expected = '/example/'
      expect(dummy_inst.normalize_path(path)).to eq(expected)
    end
  end
end
