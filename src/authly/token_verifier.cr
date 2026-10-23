module Authly
  # Verification could not be carried out (the token store is down), as opposed to the token being
  # wrong. Callers answer 503, not 401: a 401 sends every client off to re-authenticate.
  class VerificationUnavailable < Exception
  end

  # Turns a presented bearer token into verified claims. Implement it to plug in another
  # verification scheme (a remote introspection call, a key set fetched from elsewhere).
  module TokenVerifier
    # The claims of a valid access token, nil for a token that is not one. Raises
    # `VerificationUnavailable` when it cannot tell.
    abstract def verify(token : String) : Claims?
  end

  # Verifies with a `Configuration` (the global one by default), decoding the token once:
  # signature (the configured algorithm, never the token's `alg` header), `exp`, `nbf`, `iss` and
  # the revocation store for JWTs; the token store for opaque tokens.
  #
  # Only access tokens pass: `token_type` must be `access_token`. A refresh token is signed with the
  # same key but is not one. Tokens issued before `token_type` existed are accepted only with
  # `legacy_tokens: true` (they must still carry a `scope`), for the length of `access_ttl` after an
  # upgrade.
  #
  # With an `audience`, the token's `aud` must contain it. Without one any audience passes, so a token
  # minted for one API is accepted by every API sharing the key: set it.
  class StrategyTokenVerifier
    include TokenVerifier

    ACCESS_TOKEN = "access_token"

    def initialize(@config : Configuration = Authly.config, @audience : String? = nil, @legacy_tokens : Bool = false)
    end

    def verify(token : String) : Claims?
      claims = load(token)
      claims if claims && access_token?(claims) && audience_accepted?(claims)
    rescue e : VerificationUnavailable
      raise e
    rescue e
      Log.debug { "Bearer token rejected (#{e.class})" }
      nil
    end

    private def load(token : String) : Claims?
      case @config.token_strategy
      when :jwt    then load_jwt(token)
      when :opaque then load_opaque(token)
      end
    end

    private def load_jwt(token : String) : Claims?
      payload, _header = JWT.decode(token, @config.public_key, @config.algorithm, iss: @config.issuer)
      claims = Claims.from(payload.as_h)
      claims if claims.id.try { |jti| !revoked?(jti) }
    end

    private def load_opaque(token : String) : Claims?
      return if revoked?(token)

      claims = Claims.from(stored(token))
      claims if (claims["exp"]?.try(&.as_i64?) || 0_i64) > Time.utc.to_unix
    end

    # A store that cannot be reached is not a token that is wrong: say so, instead of answering
    # "invalid". Any other exception propagates and means "invalid" (see `TokenStore`).
    private def revoked?(id : String) : Bool
      available { @config.token_store.revoked?(id) }
    end

    private def stored(token : String)
      available { @config.token_store.fetch(token) }
    end

    private def available(&)
      yield
    rescue e : StoreUnavailable | IO::Error
      Log.error { "Token store unavailable (#{e.class})" }
      raise VerificationUnavailable.new("Token store unavailable", e)
    end

    private def access_token?(claims : Claims) : Bool
      return false unless claims.subject && claims["scope"]?.try(&.as_s?) && claims["exp"]?.try(&.as_i64?)

      type = claims["token_type"]?
      type ? type.as_s? == ACCESS_TOKEN : @legacy_tokens
    end

    private def audience_accepted?(claims : Claims) : Bool
      required = @audience
      required.nil? || claims.audience?(required)
    end
  end
end
