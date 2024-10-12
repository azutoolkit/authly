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
    property audience : String = "https://your-domain.com/oauth/token"
  end
end
