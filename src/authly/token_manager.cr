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

  REFRESH_TOKEN = "refresh_token"

  class JWTToken
    include TokenStrategy

    def initialize
      @config = Authly.config
    end

    def revoke(token)
      decoded_token, _header = Authly.jwt_decode(token)
      jti = decoded_token["jti"].to_s
      @config.token_store.revoke(jti)
      revoke_family(decoded_token)
    end

    # Revoking a refresh token ends everything it was rotated into, not only itself.
    private def revoke_family(claims)
      return unless claims["token_type"]?.try(&.as_s?) == REFRESH_TOKEN

      claims["fid"]?.try(&.as_s?).try { |family| RefreshToken.revoke_family(family) }
    end

    def revoked?(token : String) : Bool
      decoded_token, _header = Authly.jwt_decode(token)
      jti = decoded_token["jti"].to_s
      @config.token_store.revoked?(jti)
    end

    def valid?(token) : Bool
      decoded_token, _header = Authly.jwt_decode(token)
      return false if decoded_token["token_type"]?.try(&.as_s?) == REFRESH_TOKEN
      return false if revoked?(token)

      exp = decoded_token["exp"].to_s.to_i64
      Time.utc.to_unix < exp
    rescue e : JWT::DecodeError
      Log.debug { "Invalid token (#{e.class})" }
      false
    end

    def introspect(token : String)
      # Decode the JWT, verify the signature and expiration
      payload, _header = Authly.jwt_decode(token)

      # A refresh token is not an access token (it is redeemed at the token endpoint only)
      return {"active" => false} if payload["token_type"]?.try(&.as_s?) == REFRESH_TOKEN

      # Check if the token is revoked
      if revoked?(token)
        return {"active" => false}
      end

      # Check if the token is expired (exp claim is typically in seconds since epoch)
      if Time.local.to_unix > payload["exp"].to_s.to_i64
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
    end

    # Read at use, not at construction: the strategies are built once, before an app has
    # configured its own store.
    private def token_store : TokenStore
      @config.token_store
    end

    def revoke(token)
      token_store.revoke(token)
    end

    private def refresh_token?(payload) : Bool
      payload["token_type"]?.to_s == REFRESH_TOKEN
    end

    def revoked?(token) : Bool
      token_store.revoked?(token)
    end

    def valid?(token) : Bool
      return false if token_store.revoked?(token)

      payload = token_store.fetch(token)
      return false if payload.nil? || refresh_token?(payload)

      exp_value = payload["exp"]
      exp = exp_value.is_a?(Int64) ? exp_value : exp_value.to_s.to_i64
      Time.utc.to_unix < exp
    rescue Error | KeyError | ArgumentError
      false
    end

    def introspect(token : String)
      payload = token_store.fetch(token)
      return {"active" => false} if payload.nil? || refresh_token?(payload)

      # Check if token is expired
      exp_value = payload["exp"]
      exp = exp_value.is_a?(Int64) ? exp_value : exp_value.to_s.to_i64
      if Time.utc.to_unix > exp
        return {"active" => false, "exp" => exp}
      end

      # Return OAuth2 compliant introspection response
      scope_value = payload["scope"]
      cid_value = payload["cid"]
      sub_value = payload["sub"]

      {
        "active" => true,
        "scope"  => scope_value.is_a?(String) ? scope_value : scope_value.to_s,
        "cid"    => cid_value.is_a?(String) ? cid_value : cid_value.to_s,
        "exp"    => exp,
        "sub"    => sub_value.is_a?(String) ? sub_value : sub_value.to_s,
      }
    rescue Error
      {"active" => false}
    rescue
      {"active" => false}
    end
  end

  class TokenManager
    def self.instance
      @@instance ||= new
    end

    def initialize(
      @config = Authly.config,
      @token_manager : TokenStrategy = TokenStrategyFactory.create,
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
