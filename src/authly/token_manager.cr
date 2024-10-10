module Authly
  module TokenStrategy
    abstract def revoke(token : String)
    abstract def revoked?(token : String) : Bool
    abstract def valid?(token : String) : Bool
    abstract def introspect(token : String)
  end

  class TokenStrategyFactory
    TOKEN_MANAGERS = {
      jwt:    JWTToken.new,
      opaque: OpaqueToken.new,
    }

    def self.create
      TOKEN_MANAGERS.fetch(Authly.config.token_strategy) do
        raise Error.unsupported_token_type
      end
    end
  end

  class JWTToken
    include TokenStrategy

    def initialize
      @config = Authly.config
    end

    def revoke(token)
      decoded_token, _header = Authly.jwt_decode(token)
      jti = decoded_token["jti"].to_s
      @config.token_store.revoke(jti)
    end

    def revoked?(token) : Bool
      decoded_token, _header = Authly.jwt_decode(token)
      jti = decoded_token["jti"].to_s
      @config.token_store.revoked?(jti)
    end

    def valid?(token) : Bool
      decoded_token, _header = Authly.jwt_decode(token)
      jti = decoded_token["jti"].to_s
      return false if revoked?(jti)

      exp = decoded_token["exp"].to_s.to_i
      Time.utc.to_unix < exp
    rescue e : JWT::DecodeError
      Log.error { "Invalid token - #{e.message}" }
      false
    end

    def introspect(token : String)
      # Decode the JWT, verify the signature and expiration
      payload, _header = Authly.jwt_decode(token)

      # Check if the token is expired (exp claim is typically in seconds since epoch)
      if Time.local.to_unix > payload["exp"].to_s.to_i
        return {"active" => false, "exp" => payload["exp"].as_i64}
      end

      # Return authly access token
      {
        "active" => true,
        "scope"  => payload["scope"].as_s,
        "cid"    => payload["cid"].as_s,
        "exp"    => payload["exp"].as_i64,
        "sub"    => payload["sub"].as_s,
      }
    rescue JWT::DecodeError
      {"active" => false}
    end
  end

  class OpaqueToken
    include TokenStrategy

    def initialize
      @config = Authly.config
      @token_store = @config.token_store
    end

    def revoke(token)
      @token_store.revoke(token)
    end

    def revoked?(token) : Bool
      @token_store.revoked?(token)
    end

    def valid?(token) : Bool
      @token_store.valid?(token)
    end

    def introspect(token : String)
      payload = @token_store.fetch(token)
      return {"active" => false} if payload.nil?

      {"active" => true, "token" => payload}
    rescue e : Error
      {"active" => false}
    end
  end

  class TokenManager
    def self.instance
      @@instance ||= new
    end

    def initialize(
      @config = Authly.config,
      @token_manager : TokenStrategy = TokenStrategyFactory.create
    )
    end

    def revoke(token)
      @token_manager.revoke(token)
    end

    def revoked?(token)
      @token_manager.revoked?(token)
    end

    def valid?(token)
      @token_manager.valid?(token)
    end

    def introspect(token : String)
      @token_manager.introspect(token)
    end
  end
end
