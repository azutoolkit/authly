module Authly
  struct Code
    include JSON::Serializable
    CODE_TTL = Authly.config.code_ttl

    getter state : String,
      code : String = Random::Secure.hex(16),
      challenge = "",
      challenge_method = ""

    def initialize(@state, @challenge, @challenge_method)
    end

    def jwt(client_id, uri, state = "", scope = "")
      @value = Authly.jwt_encode({
        "cid"   => client_id,
        "uri"   => uri,
        "state" => state,
        "scope" => scope,
        "iat"   => Time.utc.to_unix,
        "exp"   => CODE_TTL.from_now.to_unix,
      })
    end

    def to_s
      @value.to_s
    end
  end
end
