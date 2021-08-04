require "uri"

module Authly
  struct AuthorizationCode
    getter client_id : String,
      client_secret : String,
      redirect_uri : String,
      code : String

    def initialize(@client_id, @client_secret, @redirect_uri, @code)
    end

    def authorize!
      raise Error.invalid_redirect_uri if redirect_uri.empty?
      raise Error.unauthorized_client if client_id.empty?
      raise Error.invalid_redirect_uri unless URI.parse(redirect_uri)
      raise Error.unauthorized_client unless client_authorized?
      Response::AccessToken.new(client_id)
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret, redirect_uri, code)
    end
  end
end
