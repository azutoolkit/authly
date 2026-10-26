module Authly
  # Raise it from a `TokenStore` that cannot be reached (Redis down, connection refused). Resource
  # servers then answer 503 instead of 401. `IO::Error` (so `Socket::Error`) counts as the same.
  class StoreUnavailable < Exception
  end

  # The contract of a token store: `fetch` raises `Authly::Error` (`Error.invalid_token`) for a token
  # it does not know, and `StoreUnavailable` when the store is down. Any other exception from a store
  # is treated as "not a valid token" (401), never as an outage, so a store that raises `KeyError` for
  # an unknown token does not let clients make the server answer 503.
  module TokenStore
    abstract def store(token_id : String, payload)
    abstract def fetch(token_id : String)
    abstract def revoke(token_id : String)
    abstract def revoked?(token_id : String) : Bool
    abstract def valid?(token_id : String) : Bool

    # Revoke `token_id` for `ttl` only: the revocation can be forgotten afterwards, because everything it covers has
    # expired by then (the family of a refresh token is revoked for `refresh_ttl`). A store that can expire keys
    # (Redis `SET key 1 EX ttl`) should override this so the revocation set does not grow forever; the default
    # keeps the revocation until the store drops it.
    def revoke(token_id : String, ttl : Time::Span)
      revoke(token_id)
    end

    # Revoke `token_id` and report whether this call was the one that revoked it, so a
    # one-time credential can be redeemed by exactly one of several concurrent requests.
    # The default is check-then-revoke; a shared store should override it with an atomic
    # operation (for Redis, `SET NX`).
    def consume(token_id : String) : Bool
      return false if revoked?(token_id)
      revoke(token_id)
      true
    end
  end

  class InMemoryStore
    include Authly::TokenStore
    include Enumerable(String)

    alias TokenPayload = String | Int64 | Bool | Float64

    # Use a set to track revoked tokens by their jti
    def initialize
      @revoked_tokens = Set(String).new
      @tokens = {} of String => Hash(String, TokenPayload)
    end

    # Implement the each method to make the class enumerable
    def each(&)
      @revoked_tokens.each { |jti| yield jti }
    end

    # Method to store a token by its jti
    def store(token_id : String, payload)
      @tokens[token_id] = payload
    end

    def fetch(token_id : String)
      @tokens.fetch(token_id) { raise Error.invalid_token }
    end

    # Method to revoke a token by its jti
    def revoke(token_id : String)
      @revoked_tokens.add(token_id)
    end

    # Method to check if a token's jti has been revoked
    def revoked?(token_id : String) : Bool
      @revoked_tokens.includes?(token_id)
    end

    def valid?(token_id : String) : Bool
      !revoked?(token_id)
    end

    def consume(token_id : String) : Bool
      @revoked_tokens.add?(token_id)
    end
  end
end
