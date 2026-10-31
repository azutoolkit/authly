module Authly
  struct Code
    include JSON::Serializable

    getter code : String = Random::Secure.hex(16),
      client_id : String,
      scope : String,
      redirect_uri : String,
      challenge = "",
      method = "",
      user_id = "",
      nonce = ""

    def initialize(
      @client_id,
      @scope,
      @redirect_uri,
      @challenge = "",
      @method = "",
      @user_id = "",
      @nonce = "",
    )
    end

    def jwt
      Authly.jwt_encode({
        "jti"          => Random::Secure.hex(32),
        "code"         => code,
        "client_id"    => client_id,
        "token_type"   => "authorization_code",
        "nonce"        => nonce,
        "challenge"    => challenge,
        "method"       => method,
        "scope"        => scope,
        "user_id"      => user_id,
        "redirect_uri" => redirect_uri,
        "iat"          => Time.utc.to_unix,
        "iss"          => Authly.config.issuer,
        "exp"          => Authly.config.code_ttl.from_now.to_unix,
      })
    end

    def to_s
      jwt
    end
  end
end
