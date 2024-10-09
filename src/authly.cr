require "jwt"
require "json"
require "./authly/authorizable_owner"
require "./authly/authorizable_client"
require "./authly/token_store_provider"
require "./authly/**"
require "log"

module Authly
  CONFIG = Configuration.instance

  alias HashToken = Hash(String, Int64 | String)

  def self.configure(&)
    with CONFIG yield CONFIG
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

  def self.encode_token(payload)
    config.token_strategy.encode(payload)
  end

  def self.decode_token(token)
    config.token_strategy.decode(token)
  end

  def self.revoke(token)
    config.token_strategy.revoke!(token)
  end

  def self.revoked?(token)
    config.token_strategy.revoked?(token)
  end

  def self.valid?(token)
    config.token_strategy.valid?(token)
  end

  def self.inspect(token : String)
    config.token_strategy.inspect(token)
  end
end
