module Authly
  module GrantStrategy
    abstract def authorized? : Bool

    # Who the issued token is about, when the grant identifies someone it can trust:
    # the client for the client credentials grant, the resource owner for grants that
    # authenticated one. Nil leaves the token with an anonymous subject.
    def subject : String?
      nil
    end

    # The scope the strategy resolved itself (the refresh token grant); nil when the grant
    # does not know it and `Grant` reads it from the authorization code.
    def granted_scope : String?
      nil
    end

    # The scope a refresh token issued by this grant keeps granting, when it differs from the access token's.
    def refresh_scope : String?
      nil
    end

    # The rotation family of the refresh token this grant redeemed, nil when it redeemed none.
    def refresh_family : String?
      nil
    end

    # When the family of the refresh token this grant redeemed stops being renewable; nil when it redeemed none
    # (a new family then gets a fresh deadline).
    def refresh_family_expires_at : Time?
      nil
    end

    # The identifier an owner carries in its ID token, which is what the `sub` of its access
    # tokens must match; the username when the owner store cannot say.
    private def owner_subject(username : String) : String
      Authly.owners.id_token(username)["sub"].to_s
    rescue
      username
    end
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
          refresh_token: args.fetch(:refresh_token, "").to_s,
          requested_scope: args.fetch(:scope, nil).try(&.to_s)
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
    @cert_thumbprint : String?

    def initialize(grant_type : String, **args)
      @grant_strategy = GrantFactory.create(grant_type, **args)
      @client_id = args.fetch(:client_id, "").to_s
      @code = args.fetch(:code, "").to_s
      @cert_thumbprint = args[:cert_thumbprint]?.try(&.to_s)
    end

    def token : AccessToken
      validate_scope!
      authorized?

      access_token
    end

    def authorized?
      @grant_strategy.authorized?
    end

    private def access_token
      AccessToken.new(
        @grant_strategy.client_id, scope, generate_id_token, @cert_thumbprint, @grant_strategy.subject,
        @grant_strategy.refresh_family, @grant_strategy.refresh_scope, @grant_strategy.refresh_family_expires_at)
    end

    private def generate_id_token
      if !@code.empty? && scope.includes? "openid"
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
      @grant_strategy.granted_scope || code_scope
    end

    private def code_scope : String
      return "" if @code.empty?
      auth_code["scope"].as_s
    end

    private def validate_scope!
      return if scope.empty?
      unless Authly.clients.allowed_scopes?(@client_id, scope)
        raise Error.invalid_scope
      end
    end
  end
end
