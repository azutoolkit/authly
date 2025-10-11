module Authly
  class ClientCredentials
    include GrantStrategy
    getter client_id : String, client_secret : String

    def initialize(@client_id, @client_secret)
    end

    def authorized? : Bool
      raise Error.unauthorized_client unless client_authorized?
      raise Error.unauthorized_client unless grant_type_authorized?
      true
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end

    private def grant_type_authorized?
      Authly.clients.allowed_grant_type?(client_id, "client_credentials")
    end
  end
end
