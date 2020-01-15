require "jwt"
require "json"

require "./authly/grant"
require "./authly/error"
require "./authly/grant"

module Authly
  class_property secret = "SOME SECRET KEY"
  class_property client : Proc(String, String, String?, Bool) = ->(client_id : String, client_secret : String, redirect_uri : String?) { true }
  class_property owner : Proc(String, String, Bool) = ->(username : String, password : String) { true }

  def self.authorize(*args)
    Grant.strategy(*args).authorize!.not_nil!
  end

  def self.code(request : CodeRequest)
    raise Error.invalid_redirect_uri unless request.valid?
    raise Error.unauthorized_client unless yield

    TemporaryCode.new(request)
  end
end
