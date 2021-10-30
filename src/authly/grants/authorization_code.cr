require "uri"

module Authly
  class AuthorizationCode
    getter client_id : String,
      client_secret : String,
      redirect_uri : String,
      code : String,
      verifier : String

    def initialize(
      @client_id, @client_secret, @redirect_uri, @code, @verifier = ""
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
      raise Error.unauthorized_client unless client_authorized?
    end

    private def verify_challenge!
      return if verifier.empty?
      raise Error.unauthorized_client unless challenge.valid?(verifier)
    end

    private def challenge
      auth_code = Authly.jwt_decode(code).first
      challenge = auth_code["challenge"].as_s
      method = auth_code["method"].as_s
      CodeChallengeBuilder.build(challenge, method)
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end
  end
end
