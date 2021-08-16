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

  def self.authorization(response_type, *args)
    ResponseType.decode(*args)
  end

  def self.token(grant_type, **args)
    Grant.new(grant_type, **args).access_token
  end
end
