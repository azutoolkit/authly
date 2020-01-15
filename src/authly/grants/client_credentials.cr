module Grants
  class ClientCredentials < Base
    def initialize(@client_id, @client_secret, @scope = "")
    end

    def authorize!
      raise Error.unauthorized_client unless client_authorized?
      AccessToken.create(client_id)
    end

    private def client_authorized?
      Authly.client.call(client_id, client_secret, nil)
    end
  end
end
