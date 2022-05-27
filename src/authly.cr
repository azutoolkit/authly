require "jwt"
require "json"

require "./authly/**"

module Authly
  CONFIG = Configuration.new

  def self.configure
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
end
