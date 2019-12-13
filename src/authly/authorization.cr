module Authly
  abstract class Authorization
    enum Types
      AuthorizationCode
      Password
      ClientCredentials
      RefreshToken
      Token
    end

    def self.build(
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
      case Types.parse(grant_type)
      when Types::AuthorizationCode then AuthorizationCode.new(client_id, client_secret, redirect_uri, code, scope, state)
      when Types::Password          then Password.new(client_id, client_secret, username, password, scope)
      when Types::ClientCredentials then ClientCredentials.new(client_id, client_secret, scope)
      when Types::RefreshToken      then RefreshToken.new(client_id, client_secret, refresh_token, scope)
      when Types::Token             then Implicit.new
      else                               Error.unsupported_grant_type
      end
    end

    abstract def authorize!
  end
end
