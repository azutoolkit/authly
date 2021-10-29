module Authly
  class ClientCredentials
    getter client_id : String, client_secret : String, scope : String

    def initialize(@client_id, @client_secret, @scope = "")
    end

    def authorized? : Bool
      raise Error.unauthorized_client unless client_authorized?
      true
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end
  end
end
