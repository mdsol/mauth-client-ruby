# frozen_string_literal: true

module MAuth
  class ConfigEnv
    GITHUB_URL = 'https://github.com/mdsol/mauth-client-ruby'

    ENV_STUFF = {
      'MAUTH_URL' => nil,
      'MAUTH_API_VERSION' => 'v1',
      'MAUTH_APP_UUID' => nil,
      'MAUTH_PRIVATE_KEY' => nil,
      'MAUTH_PRIVATE_KEY_FILE' => 'config/mauth_key',
      'MAUTH_V2_ONLY_AUTHENTICATE' => false,
      'MAUTH_V2_ONLY_SIGN_REQUESTS' => false,
      'MAUTH_DISABLE_FALLBACK_TO_V1_ON_V2_FAILURE' => false,
      'MAUTH_V1_ONLY_SIGN_REQUESTS' => true
    }.freeze

    class << self
      def load
        validate! if production?

        {
          'mauth_baseurl' => env[:mauth_url] || 'http://localhost:7000',
          'mauth_api_version' => env[:mauth_api_version],
          'app_uuid' => env[:mauth_app_uuid] || 'fb17460e-9868-11e1-8399-0090f5ccb4d3',
          'private_key' => private_key || generate_private_key,
          'v2_only_authenticate' => env[:mauth_v2_only_authenticate],
          'v2_only_sign_requests' => env[:mauth_v2_only_sign_requests],
          'disable_fallback_to_v1_on_v2_failure' => env[:mauth_disable_fallback_to_v1_on_v2_failure],
          'v1_only_sign_requests' => env[:mauth_v1_only_sign_requests]
        }
      end

      private

      def validate!
        errors = []
        errors << 'The MAUTH_URL environment variable must be set' if env[:mauth_url].nil?
        errors << 'The MAUTH_APP_UUID environment variable must be set' if env[:mauth_app_uuid].nil?
        errors << 'The MAUTH_PRIVATE_KEY environment variable must be set' if env[:mauth_private_key].nil?
        return if errors.empty?

        errors.map! { |err| "#{err} => See #{GITHUB_URL}" }
        errors.unshift('Invalid MAuth Client configuration:')
        raise errors.join("\n")
      end

      def env
        @env ||= ENV_STUFF.each_with_object({}) do |(key, default), hsh|
          env_key = key.downcase.to_sym
          hsh[env_key] = ENV.fetch(key, default)

          case default
          when TrueClass, FalseClass
            hsh[env_key] = hsh[env_key].to_s.casecmp('true').zero?
          end
        end
      end

      def production?
        environment.to_s.casecmp('production').zero?
      end

      def environment
        return Rails.environment if Object.const_defined?(:Rails) && ::Rails.respond_to?(:environment)

        ENV.fetch('RAILS_ENV') { ENV.fetch('RACK_ENV', 'development') }
      end

      def private_key
        return env[:mauth_private_key] if env[:mauth_private_key]
        return nil unless env[:mauth_private_key_file] && File.readable?(env[:mauth_private_key_file])

        File.read(env[:mauth_private_key_file])
      end

      def generate_private_key
        require 'openssl'
        OpenSSL::PKey::RSA.generate(2048).to_s
      end
    end
  end
end
