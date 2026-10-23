module Authly
  struct AccessToken
    include JSON::Serializable
    ACCESS_TTL  = Authly.config.access_ttl
    REFRESH_TTL = Authly.config.refresh_ttl

    # The subject the token was issued for: the resource owner, or the client itself for
    # the client credentials grant. A token whose grant identifies nobody gets a random one,
    # so that no two unrelated subjects ever share a `sub`.
    getter sub : String
    # The JWT ID (jti), used to track and revoke individual tokens
    getter jti : String
    getter access_token : String
    getter token_type : String = "Bearer"
    getter scope : String
    # Lifetime in seconds, as RFC 6749 section 5.1 defines `expires_in`.
    getter expires_in : Int64 = ACCESS_TTL.total_seconds.to_i64
    # Absolute expiry as a Unix timestamp (the `exp` claim).
    @[JSON::Field(ignore: true)]
    getter expires_at : Int64 = ACCESS_TTL.from_now.to_unix
    getter? revoked : Bool = false
    @[JSON::Field(emit_null: false)]
    getter refresh_token : String
    @[JSON::Field(emit_null: false)]
    getter id_token : String? = nil
    @[JSON::Field(ignore: true)]
    getter client_id : String

    def self.jwt(client_id, scope, id_token)
      new(client_id, scope, id_token).to_json
    end

    def initialize(@client_id : String, @scope : String, @id_token : String? = nil, cert_thumbprint : String? = nil, subject : String? = nil)
      @sub = subject || Random::Secure.hex(32)
      @jti = Random::Secure.hex(32)
      generator = TokenGeneratorFactory.create
      @access_token = generator.generate_access_token(@client_id, @scope, sub, @jti, cert_thumbprint)

      refresh_jti = Random::Secure.hex(32)
      @refresh_token = generator.generate_refresh_token(@client_id, refresh_jti, subject || @client_id)

      # Store metadata for opaque tokens (use access_token as key)
      expires_at = ACCESS_TTL.from_now
      if Authly.config.token_strategy == :opaque
        access_payload = {} of String => (String | Int64 | Bool | Float64)
        access_payload["cid"] = @client_id
        access_payload["scope"] = @scope
        access_payload["sub"] = sub
        access_payload["iat"] = Time.utc.to_unix
        access_payload["exp"] = expires_at.to_unix
        access_payload["token_type"] = "access_token"
        access_payload["aud"] = Authly.config.token_audience
        access_payload["jti"] = @jti

        # Add certificate thumbprint if provided
        if cert_thumbprint
          access_payload["cnf"] = cert_thumbprint
        end

        Authly.config.token_store.store(@access_token, access_payload)

        # Store refresh token metadata for opaque tokens
        refresh_payload = {} of String => (String | Int64 | Bool | Float64)
        refresh_payload["sub"] = @client_id
        refresh_payload["iat"] = Time.utc.to_unix
        refresh_payload["exp"] = REFRESH_TTL.from_now.to_unix
        refresh_payload["token_type"] = "refresh_token"
        refresh_payload["jti"] = refresh_jti
        Authly.config.token_store.store(@refresh_token, refresh_payload)
      else
        # For JWT tokens, no need to store metadata (self-contained)
        generator.store_token_metadata(@jti, @client_id, @scope, sub, expires_at, cert_thumbprint)
      end
    end
  end
end
