module Authly
  class RefreshToken
    include GrantStrategy
    getter client_id : String, client_secret : String, refresh_token : String

    def initialize(@client_id, @client_secret, @refresh_token)
    end

    def authorized? : Bool
      validate_code!
      raise Error.unauthorized_client unless client_authorized?
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
  end
end
