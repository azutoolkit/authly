module Authly
  class Configuration
    property issuer : String = "The Authority Server Provider"
    property secret_key : String = Random::Secure.hex(16)
    property public_key : String = Random::Secure.hex(16)
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
  end
end
