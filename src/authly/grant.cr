require "./grants/grant_strategy"
require "./grants/*"

module Authly
  # Factory for creating Grant strategies
  class GrantFactory
    def self.create(grant_type : String, **args) : GrantStrategy
      case grant_type
      when "authorization_code"
        AuthorizationCodeGrant.new(
          args["client_id"],
          args["client_secret"],
          args.fetch("redirect_uri", ""),
          args.fetch("challenge", ""),
          args.fetch("method", ""),
          args.fetch("verifier", "")
        )
      when "client_credentials"
        ClientCredentialsGrant.new(args["client_id"], args["client_secret"])
      when "password"
        PasswordGrant.new(
          args["client_id"],
          args["client_secret"],
          args.fetch("username", ""),
          args.fetch("password", "")
        )
      when "refresh_token"
        RefreshTokenGrant.new(
          args["client_id"],
          args["client_secret"],
          args.fetch("refresh_token", "")
        )
      else
        raise Error.unsupported_grant_type
      end
    end
  end

  # Grant class using Factory and Strategy Pattern
  class Grant
    getter grant_strategy : GrantStrategy
    @code : String

    def initialize(grant_type : String, **args)
      @grant_strategy = GrantFactory.create(grant_type, **args)
      @code = args.fetch("code", "")
    end

    def token : AccessToken
      authorized?
      access_token
    end

    def authorized? : Bool
      grant_strategy.authorized?
    end

    private def access_token
      AccessToken.new(@grant_strategy.client_id, scope, generate_id_token)
    end

    private def generate_id_token
      if scope.includes? "openid"
        user_id = auth_code["user_id"].to_s
        Authly.encode_token Authly.owners.id_token(user_id)
      end
    end

    private def auth_code
      puts Authly.decode_token(@code)
      Authly.decode_token(@code)
    end

    private def scope : String
      return "" if @code.empty?
      puts
      auth_code["scope"].to_s
    end
  end
end
