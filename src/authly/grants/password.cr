module Authly
  class Password
    include GrantStrategy
    getter client_id : String,
      client_secret : String,
      username : String,
      password : String

    def initialize(@client_id, @client_secret, @username, @password)
    end

    def subject : String?
      owner_subject(username)
    end

    def authorized? : Bool
      raise Error.unauthorized_client unless client_authorized?
      raise Error.unauthorized_client unless grant_type_authorized?
      raise Error.owner_credentials unless owner_authorized?
      true
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end

    private def grant_type_authorized?
      Authly.clients.allowed_grant_type?(client_id, "password")
    end

    private def owner_authorized?
      Authly.owners.authorized?(username, password)
    end
  end
end
