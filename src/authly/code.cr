module Authly
  struct Code
    include JSON::Serializable
    CODE_TTL = Authly.config.code_ttl

    getter code : String = Random::Secure.hex(16),
      challenge = "",
      method = "",
      scope = "",
      user_id = "",
      redirect_uri = "",
      client_id = ""

    def initialize(
      challenge = "",
      challenge_method = "",
      scope = "",
      user_id = "",
      redirect_uri = "",
      client_id = ""
    )
    end

    def jwt
      Authly.jwt_encode({
        "code"         => code,
        "challenge"    => challenge,
        "method"       => method,
        "scope"        => scope,
        "user_id"      => user_id,
        "redirect_uri" => redirect_uri,
        "iat"          => Time.utc.to_unix,
        "exp"          => CODE_TTL.from_now.to_unix,
      })
    end

    def to_s
      jwt
    end
  end
end
