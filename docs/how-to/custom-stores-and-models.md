---
description: Connect Authly to PostgreSQL and Redis by implementing AuthorizableClient, AuthorizableOwner, TokenStore, and ChallengeStore.
icon: database
---

# Implement Custom Clients, Owners & Redis Stores

Authly's built-in stores (`InMemoryStore`, `InMemoryStateStore`, `InMemoryChallengeStore`, `InMemoryPARStore`, `InMemoryDeviceCodeStore`, `InMemoryAttemptLimiter`) are designed for single-process development and testing. For production or multi-node deployments, implement Authly's store and model interfaces against your database and Redis.

{% hint style="danger" %}
**Atomicity Requirement for Shared Stores**
Single-use credentials (`TokenStore#consume`, `StateStore#consume`, `PARStore#consume`, `ChallengeStore#consume!`, and `AttemptLimiter#increment`) **must** be implemented as single atomic operations in Redis or SQL—never as a `valid?`/`fetch` check followed by a delete.
{% endhint %}

---

## 1. Implement `Authly::AuthorizableClient` & `Authly::AuthorizableOwner`

{% tabs %}
{% tab title="AuthorizableClient" %}
```crystal title="src/auth/database_clients.cr" lineNumbers="true"
class DatabaseClients
  include Authly::AuthorizableClient

  def valid_client?(client_id : String) : Bool
    !ClientRepo.find(client_id).nil?
  end

  def valid_redirect?(client_id : String, redirect_uri : String) : Bool
    client = ClientRepo.find(client_id)
    return false unless client
    client.redirect_uris.includes?(redirect_uri)
  end

  def authorized?(client_id : String, client_secret : String) : Bool
    client = ClientRepo.find(client_id)
    return false unless client && client.active?
    Crypto::Subtle.constant_time_compare(client.secret, client_secret)
  end

  def allowed_scopes?(client_id : String, scopes : String) : Bool
    client = ClientRepo.find(client_id)
    return false unless client

    requested = scopes.split(' ', remove_empty: true)
    !requested.empty? && requested.all? { |s| client.scopes.includes?(s) }
  end

  def allowed_grant_type?(client_id : String, grant_type : String) : Bool
    client = ClientRepo.find(client_id)
    return false unless client
    client.grant_types.includes?(grant_type)
  end

  def verify_challenge_response?(
    challenge : String,
    response : String,
    client_id : String = "",
    key_id : String? = nil,
    algorithm : String? = nil,
  ) : Bool
    client = ClientRepo.find(client_id)
    return false unless client

    Authly::ChallengeVerifier.verify?(
      challenge: challenge,
      response: response,
      public_key: client.public_key_pem,
      secret: client.secret,
      algorithm: algorithm,
    )
  end
end
```
{% endtab %}

{% tab title="AuthorizableOwner" %}
```crystal title="src/auth/database_owners.cr" lineNumbers="true"
class DatabaseOwners
  include Authly::AuthorizableOwner

  def authorized?(username : String, password : String) : Bool
    user = UserRepo.find_by_username(username)
    return false unless user && user.active?
    Crypto::Bcrypt::Password.new(user.password_digest).verify(password)
  end

  def id_token(user_id : String) : Hash(String, String | Int64)
    user = UserRepo.find_by_username_or_id!(user_id)
    {
      "user_id" => user.username,
      "sub"     => user.id,
      "iat"     => Time.utc.to_unix,
      "exp"     => Authly.config.access_ttl.from_now.to_unix,
      "iss"     => Authly.config.issuer,
    }
  end

  def verify_challenge_response?(
    challenge : String,
    response : String,
    identifier : String? = nil,
    username : String? = nil,
    owner_id : String? = nil,
    key_id : String? = nil,
    algorithm : String? = nil,
  ) : Bool
    target = identifier.presence || owner_id.presence || username.presence || key_id.presence
    return false unless target

    user = UserRepo.find_by_identifier(target)
    return false unless user

    Authly::ChallengeVerifier.verify?(
      challenge: challenge,
      response: response,
      public_key: user.public_key_pem,
      secret: user.shared_secret,
      algorithm: algorithm,
    )
  end
end
```
{% endtab %}
{% endtabs %}

---

## 2. Implement Redis-Backed `TokenStore` & `ChallengeStore`

{% tabs %}
{% tab title="RedisTokenStore" %}
```crystal title="src/auth/redis_token_store.cr" lineNumbers="true"
class RedisTokenStore
  include Authly::TokenStore

  def initialize(@redis : Redis::PooledClient)
  end

  def store(token_id : String, payload)
    ttl = (payload["exp"].to_s.to_i64 - Time.utc.to_unix).clamp(1_i64..)
    @redis.set("authly:token:#{token_id}", payload.to_json, ex: ttl)
  end

  def fetch(token_id : String)
    raw = @redis.get("authly:token:#{token_id}")
    raise Authly::Error.invalid_token unless raw
    JSON.parse(raw).as_h.transform_values do |v|
      v.as_i64? || v.as_f? || v.as_bool? || v.as_s
    end
  end

  def revoke(token_id : String, ttl : Time::Span = Authly.config.refresh_ttl)
    @redis.set("authly:revoked:#{token_id}", "1", ex: ttl.total_seconds.to_i)
  end

  def revoke(token_id : String)
    revoke(token_id, Authly.config.refresh_ttl)
  end

  def revoked?(token_id : String) : Bool
    @redis.exists("authly:revoked:#{token_id}") == 1
  end

  def valid?(token_id : String) : Bool
    !revoked?(token_id)
  end

  # Atomic single-use redemption via SET NX EX
  def consume(token_id : String, ttl : Time::Span = Authly.config.refresh_ttl) : Bool
    @redis.set("authly:revoked:#{token_id}", "1", nx: true, ex: ttl.total_seconds.to_i) == "OK"
  end

  def consume(token_id : String) : Bool
    consume(token_id, Authly.config.refresh_ttl)
  end
end
```
{% endtab %}

{% tab title="RedisChallengeStore" %}
```crystal title="src/auth/redis_challenge_store.cr" lineNumbers="true"
class RedisChallengeStore
  include Authly::ChallengeStore

  def initialize(@redis : Redis::PooledClient)
  end

  def store(challenge : Authly::Challenge) : Authly::Challenge
    ttl = challenge.expires_in.clamp(1..)
    @redis.set("authly:challenge:#{challenge.challenge_id}", challenge.to_json, ex: ttl)
    challenge
  end

  def fetch(challenge_id : String) : Authly::Challenge?
    raw = @redis.get("authly:challenge:#{challenge_id}")
    return unless raw
    data = Authly::Challenge.from_json(raw)
    data unless data.expired? || data.consumed?
  end

  # Atomic GETDEL ensures single-use consumption across nodes
  def consume!(challenge_id : String) : Authly::Challenge?
    raw = @redis.command(["GETDEL", "authly:challenge:#{challenge_id}"]).as?(String)
    return unless raw
    data = Authly::Challenge.from_json(raw)
    return if data.expired? || data.consumed?
    data.consumed = true
    data
  end

  def delete(challenge_id : String) : Bool
    @redis.del("authly:challenge:#{challenge_id}") > 0
  end

  def cleanup_expired : Nil
    # Redis expires keys automatically via EX
  end
end
```
{% endtab %}
{% endtabs %}

---

## 3. Register Custom Stores in `Authly.configure`

```crystal title="src/config/authly.cr"
Authly.configure do |config|
  config.clients = DatabaseClients.new
  config.owners = DatabaseOwners.new
  config.token_store = RedisTokenStore.new(redis)
  config.challenge_store = RedisChallengeStore.new(redis)
end
```
