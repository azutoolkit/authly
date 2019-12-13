require "json"

module Authly
  struct AccessToken
    include JSON::Serializable

    def self.create(client_id, redirect_uri = "")
      access_token = Token.write client_id, redirect_uri, 1.hour.from_now.to_unix
      refresh_token = Token.write client_id, redirect_uri, 1.day.from_now.to_unix
      new(access_token, refresh_token, 1.hour.from_now.to_unix, "Bearer", nil)
    end

    getter access_token : String
    getter token_type : String
    getter expires_in : Int64

    @[JSON::Field(emit_null: false)]
    getter id_token : String? = nil

    @[JSON::Field(emit_null: false)]
    getter refresh_token : String? = nil

    def initialize(@access_token, @refresh_token, @expires_in, @token_type, @id_token)
    end
  end
end
