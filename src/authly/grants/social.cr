module Authly
  class SocialGrant
    include GrantStrategy

    GRANT_TYPES = [
      "social",
      "urn:ietf:params:oauth:grant-type:social",
    ]

    getter client_id : String
    getter client_secret : String
    getter provider_name : String
    getter code : String
    getter redirect_uri : String
    getter verifier : String
    getter subject_token : String
    getter id_token : String
    getter scope : String
    getter grant_type : String
    getter subject : String? = nil
    getter profile : SocialProfile? = nil

    def initialize(
      @client_id : String,
      @client_secret : String = "",
      @provider_name : String = "",
      @code : String = "",
      @redirect_uri : String = "",
      @verifier : String = "",
      @subject_token : String = "",
      @id_token : String = "",
      @scope : String = "",
      @grant_type : String = "social",
    )
    end

    def authorized? : Bool
      raise Error.invalid_request if @client_id.empty? || @provider_name.empty?
      raise Error.invalid_request if @code.empty? && @subject_token.empty? && @id_token.empty?

      validate_client!

      provider = Authly.config.social_providers[@provider_name]?
      raise Error.invalid_request unless provider

      social_profile =
        if !@code.empty?
          provider.exchange_code(
            code: @code,
            redirect_uri: @redirect_uri.presence,
            code_verifier: @verifier.presence,
          )
        else
          provider.verify_token(
            access_token: @subject_token.presence,
            id_token: @id_token.presence,
          )
        end

      @profile = social_profile
      resolved_subject = SocialGrant.resolve_owner(social_profile)
      raise Error.access_denied unless resolved_subject

      @subject = owner_subject(resolved_subject)
      true
    end

    def granted_scope : String?
      @scope.presence || "read"
    end

    def self.resolve_owner(profile : SocialProfile) : String?
      if resolver = Authly.config.social_owner_resolver
        if sub = resolver.call(profile).try(&.strip).presence
          return sub
        end
      end

      Authly.owners.resolve_social_owner(profile).try(&.strip).presence
    end

    private def validate_client! : Nil
      if @client_secret.empty?
        raise Error.invalid_client unless Authly.clients.valid_client?(@client_id)
      else
        raise Error.invalid_client unless Authly.clients.authorized?(@client_id, @client_secret)
      end

      unless Authly.clients.allowed_grant_type?(@client_id, @grant_type) ||
             Authly.clients.allowed_grant_type?(@client_id, "social") ||
             Authly.clients.allowed_grant_type?(@client_id, "urn:ietf:params:oauth:grant-type:social")
        raise Error.unauthorized_client
      end
    end
  end
end
