module Authly
  struct RefreshToken
    getter client_id : String,
      client_secret : String,
      refresh_token : String,
      scope : String

    def initialize(@client_id, @client_secret, @refresh_token, @scope = "")
    end

    def authorize!
      validate_code!
      raise Error.unauthorized_client unless client_authorized?

      Response::AccessToken.new(client_id)
    end

    private def validate_code!
      Token.decode refresh_token
    rescue e
      raise Error.invalid_grant
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end
  end
end
