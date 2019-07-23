shared_examples MAuth::Client::AuthenticatorBase do
  context 'when v2 and v1 headers are present on the object to authenticate' do
    it 'authenticates with v2' do
      signed_request = client.signed(request)
      expect(authenticating_mc).to receive(:signature_valid_v2!).with(signed_request)
      expect(authenticating_mc).not_to receive(:signature_valid_v1!)
      authenticating_mc.authentic?(signed_request)
    end

    it "considers an authentically-signed request to be inauthentic when it's too old or too far in the future" do
      [-301, 301].each do |time_offset|
        signed_request = client.signed(request, time: Time.now.to_i + time_offset)
        message = "expected request signed at #{time_offset} seconds to be inauthentic"
        expect { authenticating_mc.authenticate!(signed_request) }.to(
          raise_error(MAuth::InauthenticError, /Time verification failed\. .* not within 300 of/),
          message
        )
      end
    end

    it "considers an authentically-signed request to be authentic when it's within the allowed time range" do
      Timecop.freeze(Time.now)
      [-300, -299, 299, 300].each do |time_offset|
        signed_request = client.signed(request, time: Time.now.to_i + time_offset)
        message = "expected request signed at #{time_offset} seconds to be authentic"
        expect(authenticating_mc.authentic?(signed_request)).to eq(true), message
      end
      Timecop.return
    end

    it "considers an authentically-signed request to be inauthentic when it has no MCC-time" do
      signed_request = client.signed(request)
      signed_request.headers.delete('MCC-Time')
      expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
        MAuth::InauthenticError,
        /Time verification failed\. No MCC-Time present\./
      )
    end

    it "considers a request with a bad V2 token to be inauthentic" do
      ['mws2', 'm.w.s', 'm w s', 'NWSv2', ' MWS'].each do |bad_token|
        signed_request = client.signed(request)
        signed_request.headers['MCC-Authentication'] = signed_request.headers['MCC-Authentication'].sub(/\AMWSV2/, bad_token)
          expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
            MAuth::InauthenticError, /Token verification failed\. Expected MWSV2; token was .*/)
      end
    end

    describe 'logging requester and requestee' do
      before do
        allow(authenticating_mc).to receive(:client_app_uuid).and_return('authenticator')
      end

      it 'logs the mauth app uuid of the requester and requestee when they both have such uuids' do
        signed_request = client.signed(request, time: Time.now.to_i)
        expect(authenticating_mc.logger).to receive(:info).with(
          'Mauth-client attempting to authenticate request from app with mauth ' \
          'app uuid signer to app with mauth app uuid authenticator using version MWSV2.'
        )
        authenticating_mc.authentic?(signed_request)
      end

      it 'logs when the mauth app uuid is not provided in the request' do
        signed_request = client.signed(request, time: Time.now.to_i)
        allow(signed_request).to receive(:signature_app_uuid).and_return(nil)
        expect(authenticating_mc.logger).to receive(:info).with(
          'Mauth-client attempting to authenticate request from app with mauth app uuid ' \
          '[none provided] to app with mauth app uuid authenticator using version MWSV2.'
        )
        authenticating_mc.authentic?(signed_request) rescue nil
      end
    end
  end

  context 'when only v1 headers are present on the object to authenticate' do

    it 'authenticates with v1' do
      expect(authenticating_mc).to receive(:signature_valid_v1!).with(v1_signed_req)
      expect(authenticating_mc).not_to receive(:signature_valid_v2!)
      authenticating_mc.authentic?(v1_signed_req)
    end

    it "considers an authentically-signed request to be inauthentic when it's too old or too far in the future" do
      [-301, 301].each do |time_offset|
        signed_request = client.signed_v1(request, time: Time.now.to_i + time_offset)
        message = "expected request signed at #{time_offset} seconds to be inauthentic"
        expect { authenticating_mc.authenticate!(signed_request) }.to(
          raise_error(MAuth::InauthenticError, /Time verification failed\. .* not within 300 of/),
          message
        )
      end
    end

    it "considers an authentically-signed request to be authentic when it's within the allowed time range" do
      Timecop.freeze(Time.now)
      [-300, -299, 299, 300].each do |time_offset|
        signed_request = client.signed_v1(request, time: Time.now.to_i + time_offset)
        message = "expected request signed at #{time_offset} seconds to be authentic"
        expect(authenticating_mc.authentic?(signed_request)).to eq(true), message
      end
      Timecop.return
    end

    it "considers an authentically-signed request to be inauthentic when it has no x-mws-time" do
      v1_signed_req.headers.delete('X-MWS-Time')
      expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
          MAuth::InauthenticError,
          /Time verification failed\. No x-mws-time present\./
        )
    end

    it "considers a request with a bad MWS token to be inauthentic" do
      ['mws', 'm.w.s', 'm w s', 'NWS', ' MWS'].each do |bad_token|
        v1_signed_req.headers['X-MWS-Authentication'] = v1_signed_req.headers['X-MWS-Authentication'].sub(/\AMWS/, bad_token)
        expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
          MAuth::InauthenticError, /Token verification failed\. Expected MWS; token was .*/)
      end
    end

    [::Faraday::Error::ConnectionFailed, ::Faraday::Error::TimeoutError].each do |error_klass|
      it "raises UnableToAuthenticate if mauth is unreachable with #{error_klass.name}" do
        allow(test_faraday).to receive(:get).and_raise(error_klass.new('')) # for the local authenticator
        allow(test_faraday).to receive(:post).and_raise(error_klass.new('')) # for the remote authenticator
        expect { authenticating_mc.authentic?(v1_signed_req) }.to raise_error(MAuth::UnableToAuthenticateError)
      end
    end

    it "raises UnableToAuthenticate if mauth errors" do
      stubs.instance_eval{ @stack.clear } #HAX
      stubs.get("/mauth/v1/security_tokens/#{app_uuid}.json") { [500, {}, []] } # for the local authenticator
      stubs.post('/mauth/v1/authentication_tickets.json') { [500, {}, []] } # for the remote authenticator
      expect { authenticating_mc.authentic?(v1_signed_req) }.to raise_error(MAuth::UnableToAuthenticateError)
    end

    describe 'logging requester and requestee' do
      before do
        allow(authenticating_mc).to receive(:client_app_uuid).and_return('authenticator')
      end

      it 'logs the mauth app uuid of the requester and requestee when they both have such uuids' do
        expect(authenticating_mc.logger).to receive(:info).with(
          'Mauth-client attempting to authenticate request from app with mauth app' \
          ' uuid signer to app with mauth app uuid authenticator using version MWS.'
        )
        authenticating_mc.authentic?(v1_signed_req)
      end

      it 'logs when the mauth app uuid is not provided in the request' do
        allow(v1_signed_req).to receive(:signature_app_uuid).and_return(nil)
        expect(authenticating_mc.logger).to receive(:info).with(
          'Mauth-client attempting to authenticate request from app with mauth app' \
          ' uuid [none provided] to app with mauth app uuid authenticator using version MWS.'
        )
        authenticating_mc.authentic?(v1_signed_req) rescue nil
      end

    end
  end

  context 'when no headers are present on the object to authenticate' do
    it "considers a request without v1 and v2 headers to be inauthentic" do
      signed_request = client.signed(request)
      signed_request.headers.delete('X-MWS-Authentication')
      signed_request.headers.delete('MCC-Authentication')
      expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
        MAuth::MAuthNotPresent,
        'Authentication Failed. No mAuth signature present; X-MWS-Authentication ' \
        'header is blank, MCC-Authentication header is blank.'
      )
    end

    it "considers a request with empty v1 and v2 headers to be inauthentic" do
      signed_request = client.signed(request)
      signed_request.headers['X-MWS-Authentication'] = ''
      signed_request.headers['MCC-Authentication'] = ''
      expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
        MAuth::MAuthNotPresent,
        'Authentication Failed. No mAuth signature present; X-MWS-Authentication' \
        ' header is blank, MCC-Authentication header is blank.'
      )
    end
  end

  context 'when v2_only_authenticate flag is true' do
    let(:v2_only_authenticate) { true }

    it 'authenticates with v2' do
      signed_request = client.signed(request)
      expect(authenticating_mc).to receive(:signature_valid_v2!).with(signed_request)
      expect(authenticating_mc).not_to receive(:signature_valid_v1!)
      authenticating_mc.authentic?(signed_request)
    end

    it 'raises MissingV2Error if v2 headers are not present and v1 headers are present' do
      expect { authenticating_mc.authenticate!(v1_signed_req) }.to raise_error(
        MAuth::MissingV2Error
      )
    end

    it 'considers a request without v2 or v1 headers to be inauthentic' do
      signed_request = client.signed(request)
      signed_request.headers.delete('MCC-Authentication')
      signed_request.headers.delete('X-MWS-Authentication')
      expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
        MAuth::MAuthNotPresent,
        'Authentication Failed. No mAuth signature present; MCC-Authentication header is blank.'
      )
    end

    it 'considers a request with an empty v2 header to be inauthentic' do
      signed_request = client.signed(request)
      signed_request.headers['MCC-Authentication'] = ''
      signed_request.headers.delete('X-MWS-Authentication')
      expect { authenticating_mc.authenticate!(signed_request) }.to raise_error(
        MAuth::MAuthNotPresent,
        'Authentication Failed. No mAuth signature present; MCC-Authentication header is blank.'
      )
    end
  end
end
