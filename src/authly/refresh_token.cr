module Authly
  class RefreshToken < Authorization
    getter client_id : String, client_secret : String, refresh_token : String, scope : String = ""

    def initialize(@client_id, @client_secret, @refresh_token, @scope)
    end

    def authorize!
      validate_code!
      raise Error.unauthorized_client unless client_authorized?
      AccessToken.create(client_id)
    end

    private def validate_code!
      Token.read refresh_token.not_nil!
    rescue e
      raise Error.invalid_grant
    end

    private def client_authorized?
      Authly.client.call(client_id, client_secret, nil)
    end
  end
end
