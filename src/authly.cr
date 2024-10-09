require "jwt"
require "json"
require "./authly/authorizable_owner"
require "./authly/authorizable_client"
require "./authly/token_store"
require "./authly/**"
require "log"

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

  def self.revoke(token)
    TokenManager.instance.revoke(token)
  end

  def self.revoked?(token)
    TokenManager.instance.revoked?(token)
  end

  def self.valid?(token)
    TokenManager.instance.valid?(token)
  end

  def self.introspect(token : String)
    TokenManager.instance.introspect(token)
  end
end
