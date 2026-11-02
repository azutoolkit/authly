---
description: Signatures and contracts for Authly's Crystal modules, structs, classes, and store interfaces.
icon: code
---

# Crystal API, Grants & Store Interfaces

This document lists the primary Crystal modules, structs, classes, and interfaces in `Authly`.

---

## Top-Level `Authly` Module (`src/authly.cr`)

```crystal title="src/authly.cr"
module Authly
  def self.configure(& : Configuration -> _)
  def self.config : Configuration
  def self.clients : AuthorizableClient
  def self.owners : AuthorizableOwner

  # Generate an authorization code or implicit token for `response_type` ("code" or "token")
  def self.code(response_type, *args)

  # Execute a grant strategy and issue an AccessToken
  def self.access_token(grant_type : String, **args) : AccessToken

  # Encode and decode JWTs using Authly.config
  def self.jwt_encode(payload, configuration : Configuration = config) : String
  def self.jwt_decode(token : String) : Tuple
  def self.jwt_decode(token : String, secret_key : String) : Tuple
  def self.decode_with(token : String, configuration : Configuration) : Tuple

  # Token lifecycle management via TokenManager
  def self.revoke(token : String)
  def self.revoked?(token : String) : Bool
  def self.valid?(token : String) : Bool
  def self.introspect(token : String)
end
```

---

## Client & Owner Interfaces

{% tabs %}
{% tab title="Authly::AuthorizableClient" %}
```crystal title="src/authly/authorizable_client.cr"
module Authly::AuthorizableClient
  abstract def valid_redirect?(client_id : String, redirect_uri : String) : Bool
  abstract def authorized?(client_id : String, client_secret : String)
  abstract def allowed_scopes?(client_id : String, scopes : String) : Bool

  def valid_client?(client_id : String) : Bool
  def client_public_key(client_id : String) : String?
  def jarm_required?(client_id : String) : Bool
  def jarm_signing_algorithm(client_id : String) : String?
  def jarm_encryption_algorithm(client_id : String) : String?
  def jarm_encryption_encoding(client_id : String) : String?

  def verify_challenge_response?(
    challenge : String,
    response : String,
    client_id : String = "",
    key_id : String? = nil,
    algorithm : String? = nil,
  ) : Bool
end
```
{% endtab %}

{% tab title="Authly::AuthorizableOwner" %}
```crystal title="src/authly/authorizable_owner.cr"
module Authly::AuthorizableOwner
  abstract def authorized?(username : String, password : String) : Bool
  abstract def id_token(user_id : String) : Hash(String, String | Int64)

  def verify_challenge_response?(
    challenge : String,
    response : String,
    identifier : String? = nil,
    username : String? = nil,
    owner_id : String? = nil,
    key_id : String? = nil,
    algorithm : String? = nil,
  ) : Bool
end
```
{% endtab %}
{% endtabs %}

---

## Store Interfaces

{% tabs %}
{% tab title="TokenStore" %}
```crystal title="src/authly/token_store.cr"
module Authly::TokenStore
  abstract def store(token_id : String, payload)
  abstract def fetch(token_id : String)
  abstract def revoke(token_id : String)
  abstract def revoked?(token_id : String) : Bool
  abstract def valid?(token_id : String) : Bool

  def revoke(token_id : String, ttl : Time::Span)
  def consume(token_id : String) : Bool
  def consume(token_id : String, ttl : Time::Span) : Bool
end
```
{% endtab %}

{% tab title="ChallengeStore & Challenge" %}
```crystal title="src/authly/challenge_store.cr"
struct Authly::Challenge
  include JSON::Serializable

  property challenge_id : String
  property challenge : String
  property client_id : String
  property username : String?
  property owner_id : String?
  property key_id : String?
  property expires_at : Time
  property? consumed : Bool
  property attempts : Int32

  def self.generate(
    client_id : String,
    ttl : Time::Span = Authly.config.challenge_ttl,
    username : String? = nil,
    owner_id : String? = nil,
    key_id : String? = nil,
  ) : Challenge

  def expired? : Bool
  def expires_in : Int32
  def identifier : String?
end

module Authly::ChallengeStore
  abstract def store(challenge : Challenge) : Challenge
  abstract def fetch(challenge_id : String) : Challenge?
  abstract def consume!(challenge_id : String) : Challenge?
  abstract def delete(challenge_id : String) : Bool
  abstract def cleanup_expired : Nil

  def valid?(challenge_id : String) : Bool
  def record_attempt!(challenge_id : String, max_attempts : Int32 = 1) : Challenge
end
```
{% endtab %}

{% tab title="StateStore, PARStore, DeviceCodeStore & AttemptLimiter" %}
```crystal
module Authly::StateStore
  abstract def store(state : String, ttl : Time::Span = 5.minutes)
  abstract def valid?(state : String) : Bool
  abstract def consume(state : String) : Bool
end

module Authly::PARStore
  abstract def store(request_uri : String, params : Hash(String, String), client_id : String, ttl : Time::Span = 90.seconds)
  abstract def fetch(request_uri : String) : PARData?
  abstract def consume(request_uri : String) : Bool
  abstract def valid?(request_uri : String) : Bool
end

module Authly::DeviceCodeStore
  abstract def store(device_code : String, data : DeviceCodeData)
  abstract def fetch(device_code : String) : DeviceCodeData?
  abstract def fetch_by_user_code(user_code : String) : DeviceCodeData?
  abstract def update(device_code : String, data : DeviceCodeData)
  abstract def delete(device_code : String)
end

module Authly::AttemptLimiter
  abstract def exceeded?(key : String, limit : Int32) : Bool
  abstract def increment(key : String, window : Time::Span) : Int32
  def record(key : String, window : Time::Span)
end
```
{% endtab %}
{% endtabs %}

---

## Cryptographic Challenge Verifier (`Authly::ChallengeVerifier`)

```crystal title="src/authly/challenge_verifier.cr"
module Authly::ChallengeVerifier
  def self.verify?(
    challenge : String,
    response : String,
    public_key : String? = nil,
    secret : String? = nil,
    algorithm : String? = nil,
  ) : Bool

  def self.verify_hmac?(
    challenge : String,
    response : String,
    secret : String,
    digest_algorithm : OpenSSL::Algorithm = OpenSSL::Algorithm::SHA256,
  ) : Bool

  def self.verify_asymmetric?(
    challenge : String,
    response : String,
    public_key : String,
    algorithm : String? = nil,
  ) : Bool
end
```

---

## Resource Server Handlers & Claims

### `Authly::Handler::Bearer`
```crystal title="src/authly/handlers/bearer_handler.cr"
Authly::Handler::Bearer.new(
  verifier : TokenVerifier = StrategyTokenVerifier.new,
  realm : String = "authly",
  prefixes : Enumerable(String)? = nil,
  except : Enumerable(String) = [] of String,
  except_exact : Enumerable(String) = [] of String,
  allow_query_token : Bool = false,
  pass_preflight : Bool = false,
)
```

### `Authly::Handler::RequireScope`
```crystal title="src/authly/handlers/require_scope_handler.cr"
Authly::Handler::RequireScope.all(*scopes : String, realm : String = "authly", prefixes = nil, except = [] of String, except_exact = [] of String, pass_preflight : Bool = false)
Authly::Handler::RequireScope.any(*scopes : String, realm : String = "authly", prefixes = nil, except = [] of String, except_exact = [] of String, pass_preflight : Bool = false)
```

### `Authly::Claims`
Retrieved via `context.authly_claims` (`Authly::Claims?`) or `context.authly_claims!` (`Authly::Claims`):
- `claims.subject : String`
- `claims.client_id : String`
- `claims.scopes : Array(String)`
- `claims.scope?(name : String) : Bool`
- `claims[claim : String] : JSON::Any`
- `claims[claim : String]? : JSON::Any?`
