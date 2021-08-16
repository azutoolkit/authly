module Authly
  struct AccessToken
    include JSON::Serializable

    def self.jwt(client_id)
      new(client_id).jwt
    end

    getter access_token : String
    getter token_type : String = "Bearer"
    getter expires_in : Int64 = 1.hour.from_now.to_unix

    @[JSON::Field(emit_null: false)]
    getter id_token : String? = nil

    @[JSON::Field(emit_null: false)]
    getter refresh_token : String?

    def initialize(@client_id, @scope)
    end

    def access_token
      JWT.encode({
        "sub" => user_id,
        "iss" => "The Oauth2 Server Provider"
        "cid" => client_id,
        "iat" => Time.utc.to_unix,
        "exp" => ACCESS_TTL.from_now.to_unix,
        "scope" => scopes,
      }, SECRET, JWT::Algorithm::HS256)
    end

    def refresh_token
      JWT.encode({
        "cid" => client_id, 
        "exp" => REFRESH_TTL.from_now.to_unix
      }, SECRET, JWT::Algorithm::HS256) 
    end
  end
end
