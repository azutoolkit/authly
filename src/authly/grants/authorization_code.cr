module Authly
  struct AuthorizationCode
    getter client_id : String,
      client_secret : String,
      redirect_uri : String,
      code : String,
      scope : String,
      state : String

    @token : JSON::Any

    delegate validate, to: Authly.clients

    def initialize(@client_id, @client_secret, @redirect_uri, @code, @scope, @state)
      @token = Token.decode(code).first
    end

    def authorize!
      raise Error.invalid_redirect_uri if redirect_uri.empty?
      raise Error.unauthorized_client unless @token["cid"] == client_id
      raise Error.invalid_redirect_uri unless @token["uri"] == redirect_uri
      raise Error.invalid_scope unless @token["scope"] == scope
      raise Error.invalid_state unless @token["state"] == state
      raise Error.unauthorized_client unless client_authorized?
      Response::AccessToken.new(client_id)
    end

    private def client_authorized?
      validate(client_id, client_secret, redirect_uri)
    end
  end
end
