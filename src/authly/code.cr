module Authly
  struct Code
    include JSON::Serializable
    CODE_TTL = Authly.config.code_ttl

    @secret_key : String = Authly.config.secret_key
    @algorithm : JWT::Algorithm = Authly.config.algorithm

    getter code : String = Random::Secure.hex(16),
      client_id : String,
      scope : String,
      redirect_uri : String,
      challenge = "",
      method = "",
      user_id = ""

    def initialize(
      @client_id,
      @scope,
      @redirect_uri,
      @challenge = "",
      @method = "",
      @user_id = ""
    )
    end

    def jwt
      JWT.encode({
        "code"         => code,
        "challenge"    => challenge,
        "method"       => method,
        "scope"        => scope,
        "user_id"      => user_id,
        "redirect_uri" => redirect_uri,
        "iss"          => Authly.config.issuer,
        "iat"          => Time.utc.to_unix,
        "exp"          => CODE_TTL.from_now.to_unix,
      }, @secret_key, @algorithm)
    end

    def to_s
      jwt
    end
  end
end
