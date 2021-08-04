require "random"

module Authly
  enum ResponseStrategy
    Code
    Token

    def strategy(client_id, redirect_uri, scope = "", state = "")
      raise Error.invalid_redirect_uri if redirect_uri.empty?
      raise Error.unauthorized_client unless authorize_client(client_id, redirect_uri)

      case self
      when Code
        code = Random::Secure.hex(16)
        Response::Code.new(code, state)
      when Token
        Response::AccessToken.new(client_id)
      else
        raise Authly::Error.invalid_response_type
      end
    end

    private def authorize_client(client_id, redirect_uri)
      Authly.clients.valid_redirect?(client_id, redirect_uri)
    end
  end
end
