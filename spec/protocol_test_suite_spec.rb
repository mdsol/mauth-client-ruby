# frozen_string_literal: true

require 'test_suite_parser'
require 'faraday'
require 'mauth/client'

describe 'MAuth Client passes the protocol test suite' do
  let(:app_uuid) { ProtocolHelper::Config.app_uuid }
  let(:pub_key) { ProtocolHelper::Config.pub_key }
  let(:request_time) { ProtocolHelper::Config.request_time }
  let(:mauth_client) { ProtocolHelper::Config.mauth_client }
  let(:signing_info) { { app_uuid: app_uuid, time: request_time } }

  before(:all) { ProtocolHelper::Config.load }

  let(:parser) { ProtocolHelper::CaseParser.new(protocol, case_dir) }
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

  let(:path) { req_attrs['url'].split('?')[0] }
  let(:query) { req_attrs['url'].split('?')[1].to_s }
  let(:rackified_auth_headers) do
    expected_auth_headers.transform_keys { |k| k.upcase.tr('-', '_').prepend('HTTP_') }
  end
  let(:mock_rack_env) do
    {
      'REQUEST_METHOD' => req_attrs['verb'],
      'PATH_INFO' => path,
      'QUERY_STRING' => query,
      'rack.input' => double('rack.input', rewind: nil, read: body)
    }.merge(rackified_auth_headers)
  end
  let(:rack_req) { MAuth::Rack::Request.new(mock_rack_env) }

  describe 'MWS protocol' do
    let(:protocol) { 'MWS' }

    ProtocolHelper::Config.cases('MWS').each do |case_dir|
      context case_dir.to_s do
        let(:case_dir) { case_dir.to_s }

        context 'signing' do
          unless /binary-body/.match?(case_dir)
            it 'generates the corect string to sign' do
              elements = faraday_req.string_to_sign_v1(signing_info).split("\n")
              expected_elements = expected_str_to_sign.split("\n")

              elements.zip(expected_elements).each do |generated_sts_element, expected_sts_element|
                expect(generated_sts_element).to eq(expected_sts_element)
              end
              expect(faraday_req.string_to_sign_v1(signing_info)).to eq(expected_str_to_sign)
            end

            it 'generates the correct signature' do
              expect(mauth_client.signature_v1(expected_str_to_sign)).to eq(expected_signature)
            end
          end

          it 'generates the correct authentication headers' do
            expect(mauth_client.signed_headers_v1(faraday_req, time: request_time)).to eq(expected_auth_headers)
          end
        end

        context 'authentication' do
          before do
            allow(Time).to receive(:now).and_return(Time.at(request_time))
            allow(mauth_client).to receive(:retrieve_public_key).and_return(pub_key)
          end

          it 'considers the authentically-signed request to be authentic' do
            expect { mauth_client.authenticate!(rack_req) }.not_to raise_error
          end
        end
      end
    end

    describe 'MWSV2 protocol' do
      let(:protocol) { 'MWSV2' }

      ProtocolHelper::Config.cases('MWSV2').each do |case_dir|
        context case_dir.to_s do
          let(:case_dir) { case_dir.to_s }

          unless /authentication-only/.match?(case_dir)
            context 'signing' do
              it 'generates the corect string to sign' do
                elements = faraday_req.string_to_sign_v2(signing_info).split("\n")
                expected_elements = expected_str_to_sign.split("\n")

                elements.zip(expected_elements).each do |generated_sts_element, expected_sts_element|
                  expect(generated_sts_element).to eq(expected_sts_element)
                end
                expect(faraday_req.string_to_sign_v2(signing_info)).to eq(expected_str_to_sign)
              end

              it 'generates the correct signature' do
                expect(mauth_client.signature_v2(expected_str_to_sign)).to eq(expected_signature)
              end

              it 'generates the correct authentication headers' do
                expect(mauth_client.signed_headers_v2(faraday_req, time: request_time)).to eq(expected_auth_headers)
              end
            end
          end

          context 'authentication' do
            before do
              allow(Time).to receive(:now).and_return(Time.at(request_time))
              allow(mauth_client).to receive(:retrieve_public_key).and_return(pub_key)
            end

            it 'considers the authentically-signed request to be authentic' do
              expect { mauth_client.authenticate!(rack_req) }.not_to raise_error
            end
          end
        end
      end
    end
  end
end
