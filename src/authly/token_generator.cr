module Authly
  module TokenGenerator
    abstract def generate_access_token(client_id : String, scope : String, sub : String, jti : String, cert_thumbprint : String? = nil) : String
    abstract def generate_refresh_token(client_id : String, jti : String) : String

    # A refresh token that remembers who it was issued for, so the access token a refresh
    # produces is about the same subject. Generators that do not override it keep issuing
    # tokens for the client.
    def generate_refresh_token(client_id : String, jti : String, sub : String) : String
      generate_refresh_token(client_id, jti)
    end

    abstract def store_token_metadata(jti : String, client_id : String, scope : String, sub : String, expires_at : Time, cert_thumbprint : String? = nil)
  end

  class JWTTokenGenerator
    include TokenGenerator

    def initialize(@config : Configuration = Authly.config)
    end

    def generate_access_token(client_id : String, scope : String, sub : String, jti : String, cert_thumbprint : String? = nil) : String
      payload = {
        "sub"        => sub,
        "iss"        => @config.issuer,
        "token_type" => "access_token",
        "cid"        => client_id,
        "iat"        => Time.utc.to_unix,
        "exp"        => @config.access_ttl.from_now.to_unix,
        "scope"      => scope,
        "jti"        => jti,
      } of String => (String | Int64 | Hash(String, String))

      @config.token_audience.try { |audience| payload["aud"] = audience }

      # Add certificate binding if thumbprint is provided
      if cert_thumbprint
        payload["cnf"] = {"x5t#S256" => cert_thumbprint}
      end

      Authly.jwt_encode(payload)
    end

    def generate_refresh_token(client_id : String, jti : String) : String
      generate_refresh_token(client_id, jti, client_id)
    end

    def generate_refresh_token(client_id : String, jti : String, sub : String) : String
      Authly.jwt_encode({
        "jti"        => jti,
        "sub"        => sub,
        "name"       => "refresh token",
        "token_type" => "refresh_token",
        "iat"        => Time.utc.to_unix,
        "iss"        => @config.issuer,
        "exp"        => @config.refresh_ttl.from_now.to_unix,
      })
    end

    def store_token_metadata(jti : String, client_id : String, scope : String, sub : String, expires_at : Time, cert_thumbprint : String? = nil)
      # JWT tokens are self-contained, no need to store metadata
    end
  end

  class OpaqueTokenGenerator
    include TokenGenerator

    def initialize(@config : Configuration = Authly.config)
    end

    def generate_access_token(client_id : String, scope : String, sub : String, jti : String, cert_thumbprint : String? = nil) : String
      Random::Secure.hex(32)
    end

    def generate_refresh_token(client_id : String, jti : String) : String
      Random::Secure.hex(32)
    end

    def store_token_metadata(jti : String, client_id : String, scope : String, sub : String, expires_at : Time, cert_thumbprint : String? = nil)
      # Store metadata for opaque tokens
      payload = {} of String => (String | Int64 | Bool | Float64)
      payload["cid"] = client_id
      payload["scope"] = scope
      payload["sub"] = sub
      payload["iat"] = Time.utc.to_unix
      payload["exp"] = expires_at.to_unix
      payload["token_type"] = "access_token"
      @config.token_audience.try { |audience| payload["aud"] = audience }

      # Add certificate thumbprint if provided
      if cert_thumbprint
        payload["cnf"] = cert_thumbprint
      end

      @config.token_store.store(jti, payload)
    end
  end

  class TokenGeneratorFactory
    TOKEN_GENERATORS = {
      jwt:    JWTTokenGenerator.new,
      opaque: OpaqueTokenGenerator.new,
    }

    def self.create
      TOKEN_GENERATORS.fetch(Authly.config.token_strategy) do
        raise Error.unsupported_token_type
      end
    end
  end
end
