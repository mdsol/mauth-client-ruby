# frozen_string_literal: true

RSpec.shared_context "with FakeConnection" do
  before do
    stub_const(
      "FakeResponse",
      Class.new do
        attr_accessor :headers, :status, :body

        def initialize
          @headers = {}
          @status = 200
        end
      end
    )

    stub_const(
      "FakeConnection",
      Class.new do
        attr_accessor :headers

        def run_request(_request_method, _request_fullpath, _request_body, request_headers)
          @headers = request_headers
          FakeResponse.new
        end
      end
    )
  end
end
