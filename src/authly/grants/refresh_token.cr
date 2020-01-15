module Grants
  class RefreshToken < Base
    getter refresh_token : String

    def initialize(@client_id, @client_secret, @refresh_token, @scope = "")
    end

    def authorize!
      validate_code!
      raise Error.unauthorized_client unless client_authorized?
      AccessToken.create(client_id)
    end

    private def validate_code!
      Authly.token_provider.new refresh_token.not_nil!
    rescue e
      raise Error.invalid_grant
    end

    private def client_authorized?
      Authly.client.call(client_id, client_secret, nil)
    end
  end
end
