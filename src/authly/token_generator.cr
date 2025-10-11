module Authly
  module TokenGenerator
    abstract def generate_access_token(client_id : String, scope : String, sub : String, jti : String) : String
    abstract def generate_refresh_token(client_id : String, jti : String) : String
    abstract def store_token_metadata(jti : String, client_id : String, scope : String, sub : String, expires_at : Time)
  end

  class JWTTokenGenerator
    include TokenGenerator

    def initialize(@config : Configuration = Authly.config)
    end

    def generate_access_token(client_id : String, scope : String, sub : String, jti : String) : String
      Authly.jwt_encode({
        "sub"   => sub,
        "iss"   => @config.issuer,
        "cid"   => client_id,
        "iat"   => Time.utc.to_unix,
        "exp"   => @config.access_ttl.from_now.to_unix,
        "scope" => scope,
        "jti"   => jti,
      })
    end

    def generate_refresh_token(client_id : String, jti : String) : String
      Authly.jwt_encode({
        "jti"  => jti,
        "sub"  => client_id,
        "name" => "refresh token",
        "iat"  => Time.utc.to_unix,
        "iss"  => @config.issuer,
        "exp"  => @config.refresh_ttl.from_now.to_unix,
      })
    end

    def store_token_metadata(jti : String, client_id : String, scope : String, sub : String, expires_at : Time)
      # JWT tokens are self-contained, no need to store metadata
    end
  end

  class OpaqueTokenGenerator
    include TokenGenerator

    def initialize(@config : Configuration = Authly.config)
    end

    def generate_access_token(client_id : String, scope : String, sub : String, jti : String) : String
      Random::Secure.hex(32)
    end

    def generate_refresh_token(client_id : String, jti : String) : String
      Random::Secure.hex(32)
    end

    def store_token_metadata(jti : String, client_id : String, scope : String, sub : String, expires_at : Time)
      # Store metadata for opaque tokens
      payload = {} of String => (String | Int64 | Bool | Float64)
      payload["cid"] = client_id
      payload["scope"] = scope
      payload["sub"] = sub
      payload["iat"] = Time.utc.to_unix
      payload["exp"] = expires_at.to_unix
      payload["token_type"] = "access_token"
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

