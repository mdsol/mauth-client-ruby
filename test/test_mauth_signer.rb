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
      app_uuid = 'app_uuid_123'
      verb = 'POST'
      request_url = 'https://example.com/resource'
      post_data = 'my_post_data'

      headers = @signer.signed_headers(app_uuid, verb, request_url, post_data)

      expected_headers = {'Authorization' => "MWS #{app_uuid}:#{@signer.generate_signature(app_uuid, verb, request_url, Time.now.to_i, post_data)}",
        'x-mws-time' => Time.now.to_i.to_s
      }

      assert_equal expected_headers, headers, "Headers don't match. It may be a race condition."
    end


  end

end
