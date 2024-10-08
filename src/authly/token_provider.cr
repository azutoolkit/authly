module Authly
  module TokenProvider
    abstract def encode(payload : Hash(String, String | Bool | Int64)) : String

    abstract def decode(token : String) : Hash(String, String | Bool | Int64)

    abstract def valid?(token : String) : Bool

    abstract def revoke(token : String)

    abstract def revoke?(token : String) : Bool

    abstract def introspect(token : String) : Hash(String, String | Bool | Int64)
  end

  # JWT Token Provider
  class JWTTokenProvider
    include TokenProvider

    def encode(payload : Hash(String, String | Bool | Int64)) : String
      JWT.encode(payload, Authly.config.security.secret_key, Authly.config.security.algorithm)
    end

    def decode(token : String) : Hash(String, String | Bool | Int64)
      decoded_token, _header = JWT.decode(token, Authly.config.security.public_key, Authly.config.security.algorithm)
      decoded_token
    end

    def valid?(token : String) : Bool
      decoded_token, _header = JWT.decode(token, Authly.config.security.public_key, Authly.config.security.algorithm)
      exp = decoded_token["exp"].to_s.to_i
      Time.utc.to_unix < exp
    rescue JWT::DecodeError
      false
    end

    def revoke(token : String)
      Authly.config.providers.jti_provider.revoke(token)
    end

    def revoke?(token : String) : Bool
      Authly.config.providers.jti_provider.revoked?(token)
    end

    def introspect(token : String) : Hash(String, String | Bool | Int64)
      payload = decode(token)
      active = valid?(token)
      {
        "active" => active,
        "scope" => payload["scope"],
        "cid" => payload["cid"],
        "exp" => payload["exp"],
        "sub" => payload["sub"]
      }
    rescue JWT::DecodeError
      {"active" => false}
    end
  end

  # Opaque Token Provider
  class OpaqueTokenProvider
    include TokenProvider

    def encode(payload : Hash(String, String | Bool | Int64)) : String
      token =  Random::Secure.hex(32)
      Authly.config.providers.jti_provider.store(token, payload)
      token
    end

    def decode(token : String) : Hash(String, String | Bool | Int64)
      Authly.config.providers.jti_provider.fetch(token) || raise Error.invalid_token
    end

    def valid?(token : String) : Bool
      !Authly.config.providers.jti_provider.revoked?(token)
    end

    def revoke(token : String)
      Authly.config.providers.jti_provider.revoke(token)
    end

    def revoke?(token : String) : Bool
      Authly.config.providers.jti_provider.revoked?(token)
    end

    def introspect(token : String) : Hash(String, String | Bool | Int64)
      payload = decode(token)
      active = valid?(token)
      {
        "active" => active,
        "scope" => payload["scope"],
        "cid" => payload["cid"],
        "exp" => payload["exp"],
        "sub" => payload["sub"]
      }
    rescue Error
      {"active" => false}
    end
  end
end
