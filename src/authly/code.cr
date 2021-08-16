module Authly
  struct Code
    include JSON::Serializable

    getter state : String,
      code : String = Random::Secure.hex(16),
      code_challenge = "",
      code_challenge_method = ""

    def initialize(@state, @code = Random::Secure.hex(16))
    end

    def jwt(client_id, uri, state = "", scope = "")
      @value = JWT.encode({
        "cid"   => client_id,
        "uri"   => uri,
        "state" => state,
        "scope" => scope,
        "exp"   => CODE_TTL.from_now.to_unix,
      }, SECRET, JWT::Algorithm::HS256)
    end

    def to_s
      @value.to_s
    end
  end
end
