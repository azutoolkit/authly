module Authly
  class RefreshToken
    include GrantStrategy
    getter client_id : String, client_secret : String, refresh_token : String

    @subject : String? = nil

    def initialize(@client_id, @client_secret, @refresh_token)
    end

    def authorized? : Bool
      raise Error.unauthorized_client unless client_authorized?
      raise Error.unauthorized_client unless grant_type_authorized?
      validate_code!
      true
    end

    # The subject the refresh token was issued for. One issued for the client itself (or by
    # an older version, which always said so) identifies nobody.
    def subject : String?
      sub = @subject
      sub unless sub == client_id
    end

    private def validate_code!
      @subject = Authly.jwt_decode(refresh_token).first["sub"]?.try(&.as_s)
    rescue
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
