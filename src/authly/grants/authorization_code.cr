module Grants
  class AuthorizationCode < Base
    getter code : String, state : String

    @token : Token

    def initialize(@client_id, @client_secret, @redirect_uri, @code, @scope, @state = "")
      @token = Authly.token_provider.new code
    end

    def authorize! : AccessToken
      invalid_redirect_uri!
      raise Error.unauthorized_client unless @token.cid == client_id
      raise Error.invalid_redirect_uri unless @token.uri == redirect_uri.to_s
      raise Error.invalid_scope unless @token.scope == scope
      raise Error.invalid_state unless @token.state == state
      raise Error.unauthorized_client unless client_authorized?

      AccessToken.create(client_id, redirect_uri.to_s)
    end

    private def invalid_redirect_uri!
      raise Error.invalid_redirect_uri unless !redirect_uri.nil? & !redirect_uri.not_nil!.host.nil?
    end

    private def client_authorized?
      Authly.client.call(client_id, client_secret, redirect_uri.to_s)
    end
  end
end
