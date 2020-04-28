module Authly
  struct ClientCredentials
    getter client_id : String, client_secret : String, scope : String

    def initialize(@client_id, @client_secret, @scope = "")
    end

    def authorize!
      raise Error.unauthorized_client unless client_authorized?
      Response::AccessToken.new(client_id)
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end
  end
end
