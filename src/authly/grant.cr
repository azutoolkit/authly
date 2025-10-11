module Authly
  module GrantStrategy
    abstract def authorized? : Bool
  end

  class GrantFactory
    def self.create(grant_type : String, **args) : GrantStrategy
      case grant_type
      when "authorization_code"
        AuthorizationCode.new(
          client_id: args[:client_id].to_s,
          client_secret: args[:client_secret].to_s,
          redirect_uri: args.fetch(:redirect_uri, "").to_s,
          code: args.fetch(:code, "").to_s,
          verifier: args.fetch(:verifier, "").to_s
        )
      when "client_credentials"
        ClientCredentials.new(
          client_id: args[:client_id].to_s,
          client_secret: args[:client_secret].to_s
        )
      when "password"
        Password.new(
          client_id: args[:client_id].to_s,
          client_secret: args[:client_secret].to_s,
          username: args.fetch(:username, "").to_s,
          password: args.fetch(:password, "").to_s
        )
      when "refresh_token"
        RefreshToken.new(
          client_id: args[:client_id].to_s,
          client_secret: args[:client_secret].to_s,
          refresh_token: args.fetch(:refresh_token, "").to_s
        )
      when "urn:ietf:params:oauth:grant-type:device_code"
        DeviceCode.new(
          client_id: args[:client_id].to_s,
          device_code: args.fetch(:device_code, "").to_s
        )
      else
        raise Error.unsupported_grant_type
      end
    end
  end

  class Grant
    @grant_strategy : GrantStrategy
    property code : String
    @client_id : String
    @token_manager : TokenManager = TokenManager.instance
    @refresh_token : String
    @cert_thumbprint : String?

    def initialize(grant_type : String, **args)
      @grant_strategy = GrantFactory.create(grant_type, **args)
      @refresh_token = args.fetch(:refresh_token, "").to_s
      @client_id = args.fetch(:client_id, "").to_s
      @code = args.fetch(:code, "").to_s
      @cert_thumbprint = args[:cert_thumbprint]?.try(&.to_s)
    end

    def token : AccessToken
      validate_scope!
      authorized?

      token = access_token
      revoke_old_refresh_token(token.access_token)
      token
    end

    def authorized?
      @grant_strategy.authorized?
    end

    def refresh_token_grant
      RefreshToken.new(client_id, client_secret, refresh_token)
    end

    private def access_token
      AccessToken.new(@grant_strategy.client_id, scope, generate_id_token, @cert_thumbprint)
    end

    private def generate_id_token
      if scope.includes? "openid"
        user_id = auth_code["user_id"].as_s
        payload = Authly.owners.id_token(user_id)
        payload["iss"] = Authly.config.issuer
        payload["aud"] = @client_id
        Authly.jwt_encode(payload)
      end
    end

    private def auth_code
      Authly.jwt_decode(@code).first
    end

    private def scope : String
      return "" if @code.empty?
      auth_code["scope"].as_s
    end

    private def validate_scope!
      return if scope.empty?
      unless Authly.clients.allowed_scopes?(@client_id, scope)
        raise Error.invalid_scope
      end
    end

    private def revoke_old_refresh_token(token : String)
      if @grant_strategy.is_a?(RefreshToken)
        @token_manager.revoke(@refresh_token)
      end
    end
  end
end
