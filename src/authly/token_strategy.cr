module Authly
  module TokenStrategy
    abstract def encode(payload : HashToken) : String
    abstract def decode(token : String)
    abstract def valid?(token : String) : Bool
    abstract def revoke!(token : String)
    abstract def revoked?(token : String) : Bool
    abstract def inspect(token : String)
  end

  # JWT Token Strategy
  class JWTToken
    include TokenStrategy

    def initialize(@config : Configuration = Authly.config)
    end

    def encode(payload : HashToken) : String
      JWT.encode(payload, @config.secret_key, @config.algorithm)
    end

    def decode(token : String)
      token, _header = JWT.decode(token, @config.public_key, @config.algorithm, iss: @config.issuer)
      token
    end

    def valid?(token : String) : Bool
      return true if decode(token)
      false
    rescue
      false
    end

    def revoke!(token : String)
      token = decode(token)
      @config.token_store.revoke!(token["jti"].to_s)
    end

    def revoked?(token : String) : Bool
      token = decode(token)
      @config.token_store.revoked?(token["jti"].to_s)
    end

    def inspect(token : String)
      return {active: false} unless valid?(token) || revoked?(token)
      {active: true, token: decode(token)}
    rescue e : Exception
      {active: false}
    end
  end

  # Opaque Token Strategy
  class OpaqueToken
    include TokenStrategy

    @token_store : TokenStoreProvider = Authly.config.token_store

    def encode(payload : HashToken) : String
      tid = Random::Secure.hex(32)
      @token_store.store(tid, payload)
      tid
    end

    def decode(token : String)
      @token_store.fetch(token) || raise Error.invalid_token
    end

    def valid?(token : String) : Bool
      decode(token)
      true
    rescue e : Error
      false
    end

    def revoke!(token : String)
      @token_store.revoke!(token)
    end

    def revoked?(token : String) : Bool
      @token_store.revoked?(token)
    end

    def inspect(token : String)
      return {active: false} unless valid?(token) || revoked?(token)
      {active: true, token: decode(token)}
    rescue e : Exception
      {active: false, error: e.message}
    end
  end
end
