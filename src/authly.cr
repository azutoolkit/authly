require "jwt"
require "json"
require "./authly/authorizable_owner"
require "./authly/authorizable_client"
require "./authly/**"

module Authly
  CONFIG = Configuration.new

  def self.configure(&)
    yield CONFIG
  end

  def self.config
    CONFIG
  end

  def self.clients
    CONFIG.clients
  end

  def self.owners
    CONFIG.owners
  end

  def self.code(response_type, *args)
    ResponseType.new(response_type, *args).decode
  end

  def self.access_token(grant_type, **args)
    Grant.new(grant_type, **args).token
  end

  def self.jwt_encode(payload)
    JWT.encode(payload, config.secret_key, config.algorithm)
  end

  def self.jwt_decode(token, secret_key = config.public_key)
    JWT.decode token, secret_key, config.algorithm
  end

  def self.introspect(token : String)
    # Decode the JWT, verify the signature and expiration
    payload, header = JWT.decode(token, SECRET, algorithm: "HS256")

    # Check if the token is expired (exp claim is typically in seconds since epoch)
    exp = payload["exp"].to_i
    if Time.now.to_unix > exp
      return  { active: false,  exp: exp }
    end

    # Return the token metadata
    {
      active: true,
      scope: payload["scope"],
      client_id: payload["client_id"],
      username: payload["sub"],  # 'sub' is commonly used for the user identifier in JWTs
      exp: exp
    }
  rescue JWT::DecodeError
    return {
      active: false
    }
  end
end
