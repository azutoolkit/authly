module Authly
  class Configuration
    property issuer : String = "The Authority Server Provider"
    property secret_key : String = Random::Secure.hex(16)
    # The key tokens are verified with. For HMAC algorithms (the default) it has to be the
    # signing key, so it follows `secret_key` until it is set to something else, such as the
    # public half of an asymmetric pair.
    setter public_key : String?
    property refresh_ttl : Time::Span = 1.day
    property code_ttl : Time::Span = 5.minutes
    property access_ttl : Time::Span = 1.hour
    property owners : AuthorizableOwner = Owners.new
    property clients : AuthorizableClient = Clients.new
    property token_store : TokenStore = InMemoryStore.new
    property algorithm : JWT::Algorithm = JWT::Algorithm::HS256
    property token_strategy : Symbol = :jwt
    property state_store : StateStore = InMemoryStateStore.new
    property device_code_store : DeviceCodeStore = InMemoryDeviceCodeStore.new

    def public_key : String
      @public_key || secret_key
    end

    # PKCE Enforcement
    property? enforce_pkce : Bool = false
    property? enforce_pkce_s256 : Bool = false

    # OpenID Connect Configuration
    property base_url : String = "http://localhost:8080"

    # Dynamic Client Registration
    property? allow_dynamic_registration : Bool = false
    property client_store : ClientStore = InMemoryClientStore.new

    # Certificate-Bound Tokens (mTLS)
    property? require_certificate_bound_tokens : Bool = false
    property trusted_ca_certificates : Array(String) = [] of String

    # Pushed Authorization Requests (PAR)
    property par_store : PARStore = InMemoryPARStore.new
    property par_ttl : Time::Span = 90.seconds
    property? require_par : Bool = false

    # JWT Secured Authorization Response Mode (JARM)
    property jarm_signing_key : String? = nil
    property jarm_signing_alg : JWT::Algorithm = JWT::Algorithm::RS256
    property jarm_encryption_key : String? = nil
    property jarm_encryption_alg : String? = nil
    property jarm_encryption_enc : String? = nil
    property default_jarm_response_mode : String? = nil
    property jarm_lifetime : Time::Span = 10.minutes
  end
end
