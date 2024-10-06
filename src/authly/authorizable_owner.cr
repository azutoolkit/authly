module Authly
  module AuthorizableOwner
    abstract def authorized?(username : String, password : String) : Bool
    abstract def id_token(user_id : String) : Hash(String, String | Int64)
  end
end
