module Authly
  # Turns a presented bearer token into verified claims. Implement it to plug in another
  # verification scheme (a remote introspection call, a key set fetched from elsewhere).
  module TokenVerifier
    # The claims of a valid access token, nil for anything else. Must not raise.
    abstract def verify(token : String) : Claims?
  end

  # Verifies with Authly's own configuration: signature (the configured algorithm, never the
  # token's `alg` header), `exp`, `nbf`, `iss` and the revocation store for JWTs, the token store for
  # opaque tokens. Only access tokens pass: a refresh token is signed with the same key but carries
  # no `scope`.
  class StrategyTokenVerifier
    include TokenVerifier

    def initialize(@config : Configuration = Authly.config, @audience : String? = nil)
    end

    def verify(token : String) : Claims?
      return unless TokenManager.new(@config).valid?(token)

      claims = load(token)
      claims if claims && access_token?(claims) && audience_accepted?(claims)
    rescue e
      Log.debug { "Bearer token rejected (#{e.class})" }
      nil
    end

    private def load(token : String) : Claims?
      case @config.token_strategy
      when :jwt
        payload, _header = Authly.jwt_decode(token)
        Claims.from(payload.as_h)
      when :opaque
        @config.token_store.fetch(token).try { |payload| Claims.from(payload) }
      end
    end

    private def access_token?(claims : Claims) : Bool
      claims.subject && claims["scope"]?.try(&.as_s?) && claims["exp"]?.try(&.as_i64?) ? true : false
    end

    private def audience_accepted?(claims : Claims) : Bool
      required = @audience
      required.nil? || claims.audience?(required)
    end
  end
end
