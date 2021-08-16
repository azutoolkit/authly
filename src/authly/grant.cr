module Authly
  class Grant
    getter grant_type : String,
      client_id : String,
      client_secret : String,
      username : String,
      password : String,
      redirect_uri : String,
      code : String,
      state : String,
      scope : String,
      verifier : String,
      refresh_token : String

    GRANTS = {
      "authorization_code" => ->authorization_code,
      "client_credentials" => ->client_credentials,
      "password"           => ->password_grant,
      "refresh_token"      => ->refresh_token_grant,
    }

    def initialize(@grant_type,
                   @client_id = "",
                   @client_secret = "",
                   @username = "",
                   @password = "",
                   @redirect_uri = "",
                   @code = "",
                   @state = "",
                   @scope = "",
                   @verifier = "",
                   @refresh_token = "")
    end

    def access_token : AccessToken
      authorized?
      access_token
    end

    def authorized?
      GRANTS[grant_type].authorized?
    rescue e
      raise Error.unsupported_grant_type
    end

    def authorization_code
      AuthorizationCode.new(client_id, redirect_uri, code, state, scope, verifier)
    end

    def client_credentials
      ClientCredentials.new(client_id, client_secret, scope)
    end

    def password_grant
      Password.new(client_id, client_secret, username, password, scope)
    end

    def refresh_token_grant
      RefreshToken.new(client_id, client_secret, refresh_token, scope)
    end

    private def access_token
      AccessToken.jwt(client_id)
    end
  end
end
