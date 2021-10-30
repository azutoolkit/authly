require "random"

module Authly
  class ResponseType
    getter type : String,
      client_id : String,
      redirect_uri : String,
      scope : String = "",
      state : String = "",
      challenge : String = "",
      challenge_method : String = ""

    def initialize(
      @type,
      @client_id,
      @redirect_uri,
      @scope = "",
      @state = "",
      @challenge = "",
      @challenge_method = ""
    )
    end

    def decode
      raise Error.invalid_redirect_uri if redirect_uri.empty?
      raise Error.unauthorized_client unless authorize_client(client_id, redirect_uri)

      case @type
      when "code"  then code
      when "token" then token
      end
    end

    def code
      Code.new state, challenge, challenge_method
    end

    def token
      AccessToken.new(client_id, scope)
    end

    private def authorize_client(client_id, redirect_uri)
      Authly.clients.valid_redirect?(client_id, redirect_uri)
    end
  end
end
