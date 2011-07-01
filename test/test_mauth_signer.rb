require 'helper'

class TestMauthSigner < Test::Unit::TestCase

  def setup
    @secret = "test secret"
    @signer = MAuth::Signer.new(@secret)
  end

  context "A Signer" do
    should "default to SHA1" do
      assert_equal 'SHA1', @signer.digest
    end

    should "have a secret" do
      assert_equal @secret, @signer.secret
    end

    should "not allow nil secrets" do
      [nil, ''].each do |bad_secret|
        assert_raise(ArgumentError) { MAuth::Signer.new(bad_secret) }
      end
    end

    should "generate a digest" do
      data = 'xyz'
      digest = @signer.send(:generate_digest, data)
      expected_digest = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.const_get('SHA1').new, @secret, data)
      assert_equal expected_digest, digest
    end

    should "generate signed headers" do
      params = {
        :app_uuid => 'app_uuid_123',
        :verb => 'POST',
        :request_url => 'https://example.com/resource',
        :post_data => 'my_post_data'
      }

      headers = @signer.signed_headers(params)
      now = Time.now

      expected_headers = {'Authorization' => "MWS #{params[:app_uuid]}:#{@signer.generate_signature(params.merge(:time => now.to_i))}",
        'x-mws-time' => now.to_i.to_s
      }

      assert_equal expected_headers, headers, "Headers don't match. It may be a race condition."
    end


  end

end
