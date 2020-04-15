require 'test_suite_parser'
require 'faraday'
require 'mauth/client'
require 'byebug'

describe 'MAuth Client passes the MWSV2 protocol test suite', integration:true do
  let(:app_uuid) { ProtocolHelper::Config.app_uuid }
  let(:request_time) { ProtocolHelper::Config.request_time }
  let(:mauth_client) { ProtocolHelper::Config.mauth_client }

  before(:all) { ProtocolHelper::Config.load }

  ProtocolHelper::Config.cases.each do |case_dir|
    context "#{case_dir}" do
      let(:parser) { ProtocolHelper::CaseParser.new(case_dir) }
      let(:req_attrs) { parser.req_attrs }
      # must have protocol and domain name so URI won't consider `//example//` test case a
      # relative uri. Without protocol and domain here URI('//example//').path => '//'
      let(:uri_obj) { URI("https://example.com#{req_attrs['url']}") }
      let(:expected_str_to_sign) { parser.sts }
      let(:expected_signature) { parser.sig }
      let(:expected_auth_headers) { parser.auth_headers }
      let(:body) { parser.req_attrs['body'] }
      let(:faraday_env) do
        {
          method: req_attrs['verb'],
          url: uri_obj,
          body: body
        }
      end
      let(:faraday_req) { MAuth::Faraday::Request.new(faraday_env) }

      unless case_dir.match?(/authentication-only/)
        context 'signing' do
          it 'generates the corect string to sign' do
            signing_info = {
              app_uuid: app_uuid,
              time: request_time
            }
            sts = faraday_req.string_to_sign_v2(signing_info)
            elements = sts.split("\n")
            expected_elements = expected_str_to_sign.split("\n")

            elements.zip(expected_elements).each do |generated_sts_element, expected_sts_element|
              expect(generated_sts_element).to eq(expected_sts_element)
            end
            expect(faraday_req.string_to_sign_v2(signing_info)).to eq(expected_str_to_sign)
          end

          it 'generates the correct signature' do
            sig = mauth_client.signature_v2(expected_str_to_sign)
            expect(sig).to eq(expected_signature)
          end

          it 'generates the correct authentication headers' do
            headers = mauth_client.signed_headers_v2(faraday_req, time: request_time)
            expect(headers).to eq(expected_auth_headers)
          end
        end
      end

      context 'authentication' do
        let(:pub_key) { ProtocolHelper::Config.pub_key }
        let(:path) { req_attrs['url'].split('?')[0] }
        let(:query) { req_attrs['url'].split('?')[1].to_s }
        let(:rackified_auth_headers) do
          expected_auth_headers.transform_keys! { |k| k.upcase.gsub('-','_').prepend('HTTP_') }
        end
        let(:mock_rack_env) do
          {
            'REQUEST_METHOD' => req_attrs['verb'],
            'PATH_INFO' => path,
            'QUERY_STRING' => query,
            'rack.input' => double('rack.input', rewind: nil, read: body)
          }.merge(rackified_auth_headers)
        end

        before do
          allow(Time).to receive(:now).and_return(Time.at(request_time))
          allow(mauth_client).to receive(:retrieve_public_key).and_return(pub_key)
        end

        it 'considers the authentically-signed request to be authentic' do
          rack_req = MAuth::Rack::Request.new(mock_rack_env)
          expect { mauth_client.authenticate!(rack_req) }.not_to raise_error
        end
      end
    end
  end
end
