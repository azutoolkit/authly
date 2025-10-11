module Authly
  class RefreshToken
    include GrantStrategy
    getter client_id : String, client_secret : String, refresh_token : String

    def initialize(@client_id, @client_secret, @refresh_token)
    end

    def authorized? : Bool
      raise Error.unauthorized_client unless client_authorized?
      raise Error.unauthorized_client unless grant_type_authorized?
      validate_code!
      true
    end

    private def validate_code!
      Authly.jwt_decode(refresh_token)
    rescue e
      raise Error.invalid_grant
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end

    private def grant_type_authorized?
      Authly.clients.allowed_grant_type?(client_id, "refresh_token")
    end
  end
end
