module Authly
  class ChallengeResponse
    include GrantStrategy

    GRANT_TYPES = {"challenge_response", "urn:ietf:params:oauth:grant-type:challenge"}

    getter client_id : String
    getter client_secret : String
    getter challenge_id : String
    getter response : String

    @subject_id : String? = nil

    def initialize(
      @client_id : String,
      @challenge_id : String,
      @response : String,
      @client_secret : String = "",
      @scope : String = "",
      @key_id : String? = nil,
      @algorithm : String? = nil,
      @grant_type : String = "challenge_response",
    )
    end

    def subject : String?
      @subject_id || @client_id
    end

    def granted_scope : String?
      @scope
    end

    def authorized? : Bool
      validate_client!
      raise Error.invalid_request if @challenge_id.empty? || @response.empty?

      challenge_data = Authly.config.challenge_store.record_attempt!(
        @challenge_id,
        Authly.config.challenge_max_attempts
      )

      unless challenge_data.client_id == @client_id
        Authly.config.challenge_store.delete(@challenge_id)
        raise Error.invalid_grant
      end

      unless verify_signature?(challenge_data)
        raise Error.invalid_grant
      end

      Authly.config.challenge_store.delete(@challenge_id)
      true
    end

    def self.create_challenge(
      client_id : String,
      username : String? = nil,
      owner_id : String? = nil,
      key_id : String? = nil,
      ttl : Time::Span = Authly.config.challenge_ttl,
    ) : Challenge
      challenge = Challenge.generate(
        client_id: client_id,
        ttl: ttl,
        username: username,
        owner_id: owner_id,
        key_id: key_id,
      )
      Authly.config.challenge_store.store(challenge)
    end

    private def validate_client! : Nil
      raise Error.invalid_client if @client_id.empty?

      if @client_secret.empty?
        raise Error.invalid_client unless Authly.clients.valid_client?(@client_id)
      else
        raise Error.invalid_client unless Authly.clients.authorized?(@client_id, @client_secret)
      end

      raise Error.unauthorized_client unless grant_type_authorized?
    end

    private def grant_type_authorized? : Bool
      Authly.clients.allowed_grant_type?(@client_id, @grant_type) ||
        Authly.clients.allowed_grant_type?(@client_id, "challenge_response") ||
        Authly.clients.allowed_grant_type?(@client_id, "urn:ietf:params:oauth:grant-type:challenge")
    end

    private def verify_signature?(challenge_data : Challenge) : Bool
      owner_id = challenge_data.owner_id.presence
      username = challenge_data.username.presence
      effective_key_id = @key_id.presence || challenge_data.key_id.presence

      if owner_target = (owner_id || username)
        verified = Authly.owners.verify_challenge_response?(
          challenge: challenge_data.challenge,
          response: @response,
          identifier: owner_target,
          username: username,
          owner_id: owner_id,
          key_id: effective_key_id,
          algorithm: @algorithm,
        )
        @subject_id = owner_subject(owner_target) if verified
        return verified
      end

      if effective_key_id
        if Authly.owners.verify_challenge_response?(
             challenge: challenge_data.challenge,
             response: @response,
             identifier: effective_key_id,
             key_id: effective_key_id,
             algorithm: @algorithm,
           )
          @subject_id = owner_subject(effective_key_id)
          return true
        end
      end

      if Authly.clients.verify_challenge_response?(
           challenge: challenge_data.challenge,
           response: @response,
           client_id: @client_id,
           key_id: effective_key_id,
           algorithm: @algorithm,
         )
        @subject_id = @client_id
        return true
      end

      if Authly.owners.verify_challenge_response?(
           challenge: challenge_data.challenge,
           response: @response,
           identifier: @client_id,
           key_id: effective_key_id,
           algorithm: @algorithm,
         )
        @subject_id = @client_id
        return true
      end

      false
    end
  end
end
