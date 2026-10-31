module Authly
  alias AdditionalClaim = String | Int64 | Bool | Float64

  struct IssuanceOptions
    RESERVED = %w[iss sub aud cid jti iat exp nbf scope token_type cnf]
    getter audience : String
    getter expires_at : Time
    getter additional_claims : Hash(String, AdditionalClaim)
    getter? issue_refresh : Bool

    def initialize(@audience, @expires_at, additional_claims = {} of String => AdditionalClaim, @issue_refresh = false)
      raise ArgumentError.new("Audience is required") if @audience.blank?
      raise ArgumentError.new("Expiration must be in the future") unless @expires_at > Time.utc
      raise ArgumentError.new("Reserved token claim") if additional_claims.keys.any? { |key| RESERVED.includes?(key) }
      @additional_claims = additional_claims.dup
    end
  end
end
