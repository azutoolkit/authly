require "./grants/**"

module Authly
  enum Grant
    AuthorizationCode
    Password
    ClientCredentials
    RefreshToken
    Token

    def self.strategy(
      grant_type = "",
      client_id = "",
      client_secret = "",
      redirect_uri = URI.parse(""),
      code = "",
      scope = "",
      state = "",
      username = "",
      password = "",
      refresh_token = ""
    )
      case parse(grant_type)
      when AuthorizationCode then Grants::AuthorizationCode.new(client_id, client_secret, redirect_uri, code, scope, state)
      when Password          then Grants::Password.new(client_id, client_secret, username, password, scope)
      when ClientCredentials then Grants::ClientCredentials.new(client_id, client_secret, scope)
      when RefreshToken      then Grants::RefreshToken.new(client_id, client_secret, refresh_token, scope)
      when Token             then Grants::Implicit.new
      else                        Error.unsupported_grant_type
      end
    end
  end
end
