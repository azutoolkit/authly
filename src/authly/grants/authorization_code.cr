require "uri"

module Authly
  class AuthorizationCode
    getter client_id : String,
      client_secret : String,
      redirect_uri : String,
      code : String,
      state : String,
      scope : String,
      verifier : String

    def initialize(
      @client_id, @client_secret, @redirect_uri, @code,
      @state = "", @scope = "", @verifier = ""
    )
    end

    def authorized? : Bool
      validate!
      verify_challenge!
      true
    end

    private def validate!
      raise Error.invalid_redirect_uri if redirect_uri.empty?
      raise Error.invalid_redirect_uri unless URI.parse(redirect_uri)
      raise Error.unauthorized_client if client_authorized?
    end

    private def verify_challenge!
      return if verifier.empty?
      raise Error.unauthorized_client unless challenge.try &.valid?(verifier)
    end

    private def challenge
      CodeChallengeBuilder.build(code)
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret, redirect_uri, code)
    end
  end
end
