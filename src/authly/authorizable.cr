module Authly
  module AuthorizableOwner
    abstract def authorized?(username : String, password : String) : Bool
    abstract def id_token(username : String, password : String) : Hash(String, String)
  end

  module AuthorizableClient
    abstract def valid_redirect?(id : String, redirect_uri : String) : Bool
    abstract def authorized?(id : String, secret : String)
    abstract def authorized?(id : String, secret : String, redirect_uri : String, code : String)
  end
end
