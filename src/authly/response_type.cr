require "random"

module Authly
  class ResponseType
    getter type : String,
      client_id : String,
      scopes : String = "",
      state : String = "",
      challenge : String = "",
      challenge_method : String = ""

    STRATEGY = {
      "code"  => Code,
      "token" => Token,
    }

    def initialize(
      @type,
      @client_id,
      @redirect_uri,
      @scope,
      @state,
      @challenge,
      @challenge_method
    )
    end

    def code
      Code.new type,
        client_id,
        redirect_uri,
        scope,
        state,
        challenge,
        challenge_method
    end

    def token
      AccessToken.new(client_id)
    end

    private def authorize_client(client_id, redirect_uri)
      Authly.clients.valid_redirect?(client_id, redirect_uri)
    end
  end
end
