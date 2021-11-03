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

    def token : AccessToken
      authorized?
      access_token
    end

    def authorized?
      grant = case grant_type
              when "authorization_code" then authorization_code
              when "client_credentials" then client_credentials
              when "password"           then password_grant
              when "refresh_token"      then refresh_token_grant
              else                           raise Error.unsupported_grant_type
              end

      grant.authorized?
    end

    def authorization_code
      AuthorizationCode.new(
        client_id,
        client_secret,
        redirect_uri,
        auth_code["challenge"].as_s,
        auth_code["method"].as_s,
        verifier
      )
    end

    def client_credentials
      ClientCredentials.new(client_id, client_secret, scope)
    end

    def password_grant
      Password.new(client_id, client_secret, username, password, scope)
    end

    def refresh_token_grant
      RefreshToken.new(client_id, client_secret, refresh_token)
    end

    private def access_token
      AccessToken.new(client_id, scope, generate_id_token)
    end

    private def generate_id_token
      if @scope.includes? "openid"
        Authly.jwt_encode Authly.owners.id_token auth_code["user_id"].as_s
      end
    end

    private def auth_code
      Authly.jwt_decode(code).first
    end
  end
end
