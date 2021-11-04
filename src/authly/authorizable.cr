module Authly
  module AuthorizableOwner
    abstract def authorized?(username : String, password : String) : Bool
    abstract def id_token(user_id : String) : Hash(String, String | Int64)
  end

  module AuthorizableClient
    abstract def valid_redirect?(client_id : String, redirect_uri : String) : Bool
    abstract def authorized?(client_id : String, client_secret : String)
  end
end
