module Authly
  struct AccessToken
    include JSON::Serializable
    ACCESS_TTL  = Authly.config.access_ttl
    REFRESH_TTL = Authly.config.refresh_ttl

    # The JWT ID (jti), used to track and revoke individual tokens
    getter jti : String
    getter access_token : String
    getter token_type : String = "Bearer"
    getter expires_in : Int64 = ACCESS_TTL.from_now.to_unix
    getter revoked : Bool = false
    @[JSON::Field(emit_null: false)]
    getter refresh_token : String
    @[JSON::Field(emit_null: false)]
    getter id_token : String? = nil
    @[JSON::Field(ignore: true)]
    getter client_id : String

    def self.jwt(client_id, scope, id_token)
      new(client_id, scope, id_token).to_json
    end

    def initialize(@client_id : String, @scope : String, @id_token : String? = nil)
      @jti = Random::Secure.hex(32) # Generate a unique jti for each token
      @access_token = generate_token
      @refresh_token = refresh_token
    end

    private def generate_token
      Authly.jwt_encode({
        "sub"   => Random::Secure.hex(32),
        "iss"   => Authly.config.issuer,
        "cid"   => @client_id,
        "iat"   => Time.utc.to_unix,
        "exp"   => ACCESS_TTL.from_now.to_unix,
        "scope" => @scope,
        "jti"   => @jti, # Include the jti in the token claims
      })
    end

    def refresh_token
      Authly.jwt_encode({
        "sub"  => @client_id,
        "name" => "refresh token",
        "iat"  => Time.utc.to_unix,
        "exp"  => REFRESH_TTL.from_now.to_unix,
      })
    end
  end
end
