module Authly
  struct AccessToken
    include JSON::Serializable
    ACCESS_TTL  = Authly.config.access_ttl
    REFRESH_TTL = Authly.config.refresh_ttl

    def self.jwt(client_id, scope, id_token)
      new(client_id, scope, id_token).to_json
    end

    getter access_token : String
    getter token_type : String = "Bearer"
    getter expires_in : Int64 = 1.hour.from_now.to_unix

    @[JSON::Field(emit_null: false)]
    getter id_token : String? = nil

    @[JSON::Field(emit_null: false)]
    getter refresh_token : String?

    def initialize(@client_id : String, @scope : String, @id_token = nil)
      @access_token = generate_token
      @refresh_token = refresh_token
    end

    private def generate_token
      Authly.jwt_encode({
        "sub"   => Random::Secure.hex(32),
        "iss"   => "The Oauth2 Server Provider",
        "cid"   => @client_id,
        "iat"   => Time.utc.to_unix,
        "exp"   => ACCESS_TTL.from_now.to_unix,
        "scope" => @scope,
      })
    end

    private def refresh_token
      Authly.jwt_encode({
        "sub"  => @client_id,
        "name" => "refresh token",
        "iat"  => Time.utc.to_unix,
        "exp"  => REFRESH_TTL.from_now.to_unix,
      })
    end
  end
end
