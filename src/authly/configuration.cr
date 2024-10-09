module Authly
  # Configuration class using Singleton and Builder Pattern
  class Configuration
    class_getter instance : Configuration = Configuration.new

    property owners : AuthorizableOwner = Owners.new
    property clients : AuthorizableClient = Clients.new
    property token_store : TokenStoreProvider = InMemoryTokenStore.new
    property secret_key : String = Random::Secure.hex(16)
    property public_key : String = Random::Secure.hex(16)
    property algorithm : JWT::Algorithm = JWT::Algorithm::HS256
    property issuer : String = "The Authority Server Provider"
    property refresh_ttl : Time::Span = 1.day
    property code_ttl : Time::Span = 5.minutes
    property access_ttl : Time::Span = 1.hour
    property token_type : String = "jwt"
    getter token_strategy : TokenStrategy do
      TokenFactory.create
    end
  end
end
