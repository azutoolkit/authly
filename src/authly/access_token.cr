module Authly
  struct AccessToken
    include JSON::Serializable

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
    getter expires_in : Int64
    # Absolute expiry as a Unix timestamp (the `exp` claim).
    @[JSON::Field(ignore: true)]
    getter expires_at : Int64
    getter? revoked : Bool = false
    @[JSON::Field(emit_null: false)]
    getter refresh_token : String? = nil
    @[JSON::Field(emit_null: false)]
    getter id_token : String? = nil
    @[JSON::Field(ignore: true)]
    getter client_id : String

    def self.jwt(client_id, scope, id_token)
      new(client_id, scope, id_token).to_json
    end

    # `family` is the rotation family of the refresh token this one replaces (a new one when nil);
    # `refresh_scope` is the scope the refresh token keeps granting (`scope` when nil), which stays
    # the original one when an access token was narrowed on refresh. `family_expires_at` is the end of that family
    # (a new family ends `refresh_absolute_ttl` from now).
    def initialize(@client_id : String, @scope : String, @id_token : String? = nil, cert_thumbprint : String? = nil, subject : String? = nil,
                   family : String? = nil, refresh_scope : String? = nil, family_expires_at : Time? = nil, options : IssuanceOptions? = nil)
      issued_at = Time.utc
      expiry = options.try(&.expires_at) || issued_at + Authly.config.access_ttl
      @expires_at = expiry.to_unix
      @expires_in = @expires_at - issued_at.to_unix
      raise ArgumentError.new("Expiration must be in the future") unless @expires_in > 0
      @sub = subject || Random::Secure.hex(32)
      @jti = Random::Secure.hex(32)
      generator = TokenGeneratorFactory.create
      @access_token = generator.generate_access_token(@client_id, @scope, sub, @jti, cert_thumbprint, options, issued_at, expiry)

      refresh_jti = Random::Secure.hex(32)
      if options ? options.issue_refresh? : Authly.config.issue_refresh_tokens?
        @refresh_token = generator.generate_refresh_token(
          @client_id, refresh_jti, subject || @client_id, refresh_scope || @scope, family || Random::Secure.hex(16),
          family_expires_at || Authly.config.refresh_absolute_ttl.from_now)
      end

      if Authly.config.token_strategy == :opaque
        store_opaque_metadata(issued_at, expiry, cert_thumbprint, options, refresh_jti)
      else
        # For JWT tokens, no need to store metadata (self-contained)
        generator.store_token_metadata(@jti, @client_id, @scope, sub, expiry, cert_thumbprint)
      end
    end

    # Store metadata for opaque tokens (use access_token as key)
    private def store_opaque_metadata(issued_at : Time, expires_at : Time, cert_thumbprint : String?, options : IssuanceOptions?, refresh_jti : String)
      access_payload = {} of String => (String | Int64 | Bool | Float64)
      access_payload["cid"] = @client_id
      access_payload["scope"] = @scope
      access_payload["sub"] = sub
      access_payload["iat"] = issued_at.to_unix
      access_payload["exp"] = expires_at.to_unix
      access_payload["token_type"] = "access_token"
      Authly.config.token_audience.try { |audience| access_payload["aud"] = audience }
      access_payload["jti"] = @jti

      # Add certificate thumbprint if provided
      if cert_thumbprint
        access_payload["cnf"] = cert_thumbprint
      end

      if options
        access_payload["aud"] = options.audience
        options.additional_claims.each do |key, value|
          raise ArgumentError.new("Reserved token claim") if IssuanceOptions::RESERVED.includes?(key)
          access_payload[key] = value
        end
      end
      Authly.config.token_store.store(@access_token, access_payload)

      if refresh = @refresh_token
        # Store refresh token metadata for opaque tokens
        refresh_payload = {} of String => (String | Int64 | Bool | Float64)
        refresh_payload["cid"] = @client_id
        refresh_payload["sub"] = @client_id
        refresh_payload["iat"] = Time.utc.to_unix
        refresh_payload["exp"] = Authly.config.refresh_ttl.from_now.to_unix
        refresh_payload["token_type"] = "refresh_token"
        refresh_payload["jti"] = refresh_jti
        Authly.config.token_store.store(refresh, refresh_payload)
      end
    end
  end
end
