module Authly
  class ClientCredentials
    include GrantStrategy
    getter client_id : String, client_secret : String

    def initialize(@client_id, @client_secret)
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
