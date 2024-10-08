module Authly
  class RefreshTokenGrant < GrantStrategy
    getter client_id : String
    @client_secret : String
    @refresh_token : String

    def initialize(@client_id : String, @client_secret : String, @refresh_token : String)
    end

    def authorized? : Bool
      validate_refresh_token!
      validate_client!
      true
    end

    private def validate_refresh_token!
      Authly.decode_token(@refresh_token)
    rescue e
      raise Error.invalid_grant
    end

    private def validate_client!
      raise Error.unauthorized_client unless client_authorized?
    end

    private def client_authorized?
      Authly.clients.authorized?(@client_id, @client_secret)
    end
  end
end
