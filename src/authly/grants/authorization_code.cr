require "uri"

module Authly
  class AuthorizationCode
    getter client_id : String,
      client_secret : String,
      redirect_uri : String,
      verifier : String,
      challenge : String,
      method : String

    def initialize(
      @client_id, @client_secret, @redirect_uri, @challenge = "", @method = "", @verifier = ""
    )
    end

    def authorized? : Bool
      validate!
      verify_challenge!
      true
    end

    private def validate!
      raise Error.invalid_redirect_uri unless valid_redirect?
      raise Error.unauthorized_client unless client_authorized?
    end

    private def verify_challenge!
      return if verifier.empty?
      raise Error.unauthorized_client unless code_challenge.valid?(verifier)
    end

    private def code_challenge
      CodeChallengeBuilder.build(challenge, method)
    end

    private def valid_redirect?
      Authly.clients.valid_redirect?(client_id, redirect_uri)
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end
  end
end
