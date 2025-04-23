# frozen_string_literal: true

require "jwt"
require "json"
require "anycable-rails"

require "anycable/rails/jwt/version"
require "anycable/rails/jwt/config"

module AnyCable
  module Rails
    module JWT
      ALGORITHM = "HS256"

      class << self
        def encode(expires_at: nil, **identifiers)
          key = AnyCable.config.jwt_id_key
          raise ArgumentError, "JWT encryption key is not specified. Add it via `jwt_id_key` option" if key.nil? || key.empty?

          expires_at ||= AnyCable.config.jwt_id_ttl.seconds.from_now

          payload = {
            ext: identifiers,
            exp: expires_at.to_i
          }

          ::JWT.encode(payload, key, ALGORITHM)
        end

        def decode(token)
          key = AnyCable.config.jwt_id_key
          raise ArgumentError, "JWT encryption key is not specified. Add it via `jwt_id_key` option" if key.nil? || key.empty?

          decoded_token = ::JWT.decode(token, key, true, algorithm: ALGORITHM)
          decoded_token.first["ext"]
        end
      end
    end
  end
end

require "anycable/rails/jwt/railtie" if defined?(Rails::Railtie)
