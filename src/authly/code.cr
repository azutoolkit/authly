module Authly
  struct Code
    include JSON::Serializable
    CODE_TTL = Authly.config.code_ttl

    getter code : String = Random::Secure.hex(16),
      challenge = "",
      method = ""

    def initialize(@challenge = "", @method = "")
    end

    def jwt
      Authly.jwt_encode({
        "code"      => code,
        "challenge" => challenge,
        "method"    => method,
        "iat"       => Time.utc.to_unix,
        "exp"       => CODE_TTL.from_now.to_unix,
      })
    end

    def to_s
      jwt
    end
  end
end
