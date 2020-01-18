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

  def self.authorize(grant_type, *args)
    GrantStrategy.parse(grant_type).strategy(*args)
  end

  def self.response(response_type, *args)
    ResponseStrategy.parse(response_type).strategy(*args)
  end
end
