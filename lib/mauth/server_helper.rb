# frozen_string_literal: true

module MAuth
  module ServerHelper
    def app_uuid(request)
      request.env[MAuth::Client::RACK_ENV_APP_UUID_KEY]
    end

    def app_uuid_from_env(env)
      env[MAuth::Client::RACK_ENV_APP_UUID_KEY]
    end
  end
end
