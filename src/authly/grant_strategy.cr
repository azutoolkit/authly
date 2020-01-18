module Authly
  enum GrantStrategy
    AuthorizationCode
    ClientCredentials
    Password
    RefreshToken

    def strategy(
      client_id : String = "",
      client_secret : String = "",
      redirect_uri : String = "",
      code : String = "",
      scope : String = "",
      state : String = "",
      username : String = "",
      password : String = "",
      refresh_token : String = ""
    )
      case self
      when AuthorizationCode then Authly::AuthorizationCode.new(client_id, client_secret, redirect_uri, code, scope, state)
      when Password          then Authly::Password.new(client_id, client_secret, username, password, scope)
      when ClientCredentials then Authly::ClientCredentials.new(client_id, client_secret, scope)
      when RefreshToken      then Authly::RefreshToken.new(client_id, client_secret, refresh_token, scope)
      else                        raise Authly::Error.unsupported_grant_type
      end
    end
  end
end
