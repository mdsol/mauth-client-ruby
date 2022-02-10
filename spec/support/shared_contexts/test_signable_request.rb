# frozen_string_literal: true

require "mauth/request_and_response"

RSpec.shared_context "with TestSignableRequest" do
  before do
    stub_const(
      "TestSignableRequest",
      Class.new(MAuth::Request) do
        include MAuth::Signed
        attr_accessor :headers

        def merge_headers(headers)
          self.class.new(@attributes_for_signing).tap { |r| r.headers = (@headers || {}).merge(headers) }
        end

        def x_mws_time
          headers["X-MWS-Time"]
        end

        def x_mws_authentication
          headers["X-MWS-Authentication"]
        end

        def mcc_authentication
          headers["MCC-Authentication"]
        end

        def mcc_time
          headers["MCC-Time"]
        end
      end
    )
  end
end
