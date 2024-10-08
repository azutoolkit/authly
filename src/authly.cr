require "jwt"
require "json"
require "./authly/authorizable_owner"
require "./authly/authorizable_client"
require "./authly/jti_provider"
require "./authly/**"
require "log"

module Authly
  CONFIG = Configuration.instance

  def self.configure(&)
    yield CONFIG
  end

  def self.config
    CONFIG
  end

  def self.clients
    CONFIG.providers.clients
  end

  def self.owners
    CONFIG.providers.owners
  end

  def self.code(response_type, *args)
    ResponseType.new(response_type, *args).decode
  end

  def self.access_token(grant_type, **args)
    Grant.new(grant_type, **args).token
  end

  def self.encode_token(payload)
    token_manager = TokenManager.new
    token_manager.encode(payload)
  end

  def self.decode_token(token)
    token_manager = TokenManager.new
    token_manager.decode(token)
  end

  def self.revoke(token)
    token_manager = TokenManager.new
    token_manager.revoke(token)
  end

  def self.revoke?(token)
    token_manager = TokenManager.new
    token_manager.revoke?(token)
  end

  def self.valid?(token)
    token_manager = TokenManager.new
    token_manager.valid?(token)
  end

  def self.introspect(token : String)
    token_manager = TokenManager.new
    token_manager.introspect(token)
  end
end
