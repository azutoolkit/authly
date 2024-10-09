module Authly
  class TokenManager

    def self.instance
      @@instance ||= new
    end

    def initialize
      @config = Authly.config
    end

    def revoke(jti)
      @config.revoke_provider.revoke(jti)
    end

    def revoked?(jti)
      @config.revoke_provider.revoked?(jti)
    end

    def valid?(token)
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
        return {active: false, exp: payload["exp"]}
      end

      # Return authly access token
      {
        active: true,
        scope:  payload["scope"],
        cid:    payload["cid"],
        exp:    payload["exp"],
        sub:    payload["sub"],
      }
    rescue JWT::DecodeError
      {active: false}
    end
  end
end
