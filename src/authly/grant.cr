module Authly
  module GrantStrategy
    abstract def authorized? : Bool
  end

  class GrantFactory
    def self.create(grant_type : String, **args) : GrantStrategy
      case grant_type
      when "authorization_code"
        AuthorizationCode.new(
          args["client_id"],
          args["client_secret"],
          args.fetch("redirect_uri", ""),
          args.fetch("challenge", ""),
          args.fetch("method", ""),
          args.fetch("verifier", "")
        )
      when "client_credentials"
        ClientCredentials.new(args["client_id"], args["client_secret"])
      when "password"
        Password.new(
          args["client_id"],
          args["client_secret"],
          args.fetch("username", ""),
          args.fetch("password", "")
        )
      when "refresh_token"
        RefreshToken.new(
          args["client_id"],
          args["client_secret"],
          args.fetch("refresh_token", "")
        )
      else
        raise Error.unsupported_grant_type
      end
    end
  end

  class Grant
    @grant_strategy : GrantStrategy
    @code : String

    def initialize(grant_type : String, **args)
      @grant_strategy = GrantFactory.create(grant_type, **args)
      @code = args.fetch("code", "")
    end

    def token : AccessToken
      authorized?
      access_token
    end

    def authorized?
      @grant_strategy.authorized?
    end

    def refresh_token_grant
      RefreshToken.new(client_id, client_secret, refresh_token)
    end

    private def access_token
      AccessToken.new(@grant_strategy.client_id, scope, generate_id_token)
    end

    private def generate_id_token
      if scope.includes? "openid"
        Authly.jwt_encode Authly.owners.id_token auth_code["user_id"].as_s
      end
    end

    private def auth_code
      Authly.jwt_decode(@code).first
    end

    private def scope : String
      return "" if @code.empty?
      auth_code["scope"].as_s
    end
  end
end
