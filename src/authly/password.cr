module Authly
  class Password < Authorization
    getter client_id : String, client_secret : String, username : String, password : String, scope : String = ""

    def initialize(@client_id, @client_secret, @username, @password, @scope)
    end

    def authorize!
      raise Error.unauthorized_client unless client_authorized?
      raise Error.owner_credentials unless owner_authorized?

      AccessToken.create(client_id)
    end

    private def client_authorized?
      Authly.client.call(client_id, client_secret, nil)
    end

    private def owner_authorized?
      Authly.owner.call(username, password)
    end
  end
end
