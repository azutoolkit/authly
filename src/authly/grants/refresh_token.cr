module Authly
  # Redeems a refresh token (RFC 6749 section 6) with the hardening of OAuth 2.0 Security BCP /
  # OAuth 2.1: the token must be a refresh token issued to the authenticating client, unexpired and
  # not revoked and within the absolute lifetime of its family (`refresh_absolute_ttl`); it is single use (the answer carries a replacement from the same family); presenting
  # one that was already used revokes the whole family; the scope may only narrow.
  class RefreshToken
    include GrantStrategy
    getter client_id : String, client_secret : String, refresh_token : String

    FAMILY_PREFIX = "refresh-family:"

    @subject : String? = nil
    @original_scope = ""
    @scope = ""
    @family = ""
    @family_expires_at : Time? = nil

    def initialize(@client_id, @client_secret, @refresh_token, @requested_scope : String? = nil)
    end

    def authorized? : Bool
      raise Error.unauthorized_client unless client_authorized?
      raise Error.unauthorized_client unless grant_type_authorized?
      claims = decode_claims
      validate!(claims)
      redeem!(claims["jti"].as_s)
      true
    end

    # The subject the refresh token was issued for. One issued for the client itself (or by
    # an older version, which always said so) identifies nobody.
    def subject : String?
      sub = @subject
      sub unless sub == client_id
    end

    # The scope of the access token this redemption yields: the original one, or the narrower one asked for.
    def granted_scope : String?
      @scope
    end

    # The scope the replacement refresh token keeps granting, whatever this access token was narrowed to.
    def refresh_scope : String?
      @original_scope
    end

    def refresh_family : String?
      @family
    end

    def refresh_family_expires_at : Time?
      @family_expires_at
    end

    # Ends the family of a refresh token: nothing it was rotated into works any more. The record only has to
    # outlive the tokens it covers, so a store that can expire keys is given `refresh_ttl`.
    def self.revoke_family(family : String)
      Authly.config.token_store.revoke(FAMILY_PREFIX + family, Authly.config.refresh_ttl)
    end

    private def decode_claims : Hash(String, JSON::Any)
      Authly.jwt_decode(refresh_token).first.as_h
    rescue
      raise Error.invalid_grant
    end

    private def validate!(claims : Hash(String, JSON::Any))
      raise Error.invalid_grant unless claims["token_type"]?.try(&.as_s?) == "refresh_token"
      raise Error.invalid_grant unless claims["cid"]?.try(&.as_s?) == client_id
      @family = claims["fid"]?.try(&.as_s?) || raise Error.invalid_grant
      @original_scope = claims["scope"]?.try(&.as_s?) || raise Error.invalid_grant
      @subject = claims["sub"]?.try(&.as_s?)
      raise Error.invalid_grant if token_store.revoked?(FAMILY_PREFIX + @family)
      deadline = family_deadline(claims)
      raise Error.invalid_grant if Time.utc >= deadline
      @family_expires_at = deadline
      @scope = narrowed_scope
      raise Error.invalid_scope unless client_may_have_scope?
    end

    # `fexp`, or for a token that predates it the end of a family that began with that token.
    private def family_deadline(claims : Hash(String, JSON::Any)) : Time
      if fexp = claims["fexp"]?.try(&.as_i64?)
        Time.unix(fexp)
      else
        Time.unix(claims["iat"]?.try(&.as_i64?) || raise Error.invalid_grant) + Authly.config.refresh_absolute_ttl
      end
    end

    # The client's allowed scopes may have shrunk since the token was issued.
    private def client_may_have_scope? : Bool
      @scope.empty? || Authly.clients.allowed_scopes?(client_id, @scope)
    end

    # Exactly one of several presentations of a token redeems it. A second one means the token leaked
    # (or the client lost the answer): the family is revoked, so neither party keeps a working token.
    private def redeem!(jti : String)
      return if token_store.consume(jti)
      RefreshToken.revoke_family(@family)
      raise Error.invalid_grant
    end

    private def narrowed_scope : String
      requested = @requested_scope.presence
      return @original_scope unless requested

      granted = @original_scope.split(' ', remove_empty: true)
      raise Error.invalid_scope unless requested.split(' ', remove_empty: true).all? { |scope| granted.includes?(scope) }
      requested
    end

    private def token_store : TokenStore
      Authly.config.token_store
    end

    private def client_authorized?
      Authly.clients.authorized?(client_id, client_secret)
    end

    private def grant_type_authorized?
      Authly.clients.allowed_grant_type?(client_id, "refresh_token")
    end
  end
end
