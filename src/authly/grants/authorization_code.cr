require "uri"

module Authly
  class AuthorizationCode
    include GrantStrategy

    getter client_id : String,
      client_secret : String,
      redirect_uri : String,
      verifier : String,
      challenge : String,
      method : String,
      code : String

    def initialize(
      @client_id, @client_secret, @redirect_uri, @code = "", @verifier = ""
    )
      @challenge = ""
      @method = ""
    end

    def authorized? : Bool
      decode_code unless @code.empty?
      validate!
      verify_challenge!
      true
    end

    private def decode_code
      decoded = Authly.jwt_decode(@code).first
      @challenge = decoded["challenge"].as_s
      @method = decoded["method"].as_s
      code_redirect_uri = decoded["redirect_uri"].as_s

      # Validate redirect_uri matches the one in the code
      unless code_redirect_uri == @redirect_uri
        raise Error.invalid_redirect_uri
      end
    rescue e : Error
      # Re-raise Authly errors as-is
      raise e
    rescue e
      # For other errors (JWT decode failures, etc), raise invalid_grant
      raise Error.invalid_grant
    end

    private def validate!
      raise Error.invalid_redirect_uri unless valid_redirect?
      raise Error.unauthorized_client unless client_authorized?
      raise Error.unauthorized_client unless grant_type_authorized?
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

    private def grant_type_authorized?
      Authly.clients.allowed_grant_type?(client_id, "authorization_code")
    end
  end
end
