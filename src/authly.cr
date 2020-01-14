require "jwt"
require "json"

require "./authly/**"

module Authly
  VERSION = "0.1.0"
  alias AppModel = Proc(String, String, String?, Bool)
  alias OwnerModel = Proc(String, String, Bool)

  class_property secret = "SOME SECRET KEY"
  class_property client : AppModel = ->(client_id : String, client_secret : String, redirect_uri : String?) { true }
  class_property owner : OwnerModel = ->(username : String, password : String) { true }

  def self.authorize(*args)
    Authorization.build(*args).authorize!.not_nil!
  end

  def self.code(request : CodeRequest)
    raise Error.invalid_redirect_uri unless request.valid?
    raise Error.unauthorized_client unless yield
    TemporaryCode.new(request)
  end
end
