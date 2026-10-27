module Authly
  # A `TokenStore` in Redis, shared by every node. A token's payload lives until its `exp` (or *token_ttl* when it
  # has none); a revocation lives for the TTL it is given, or *revocation_ttl*, which must outlive every token
  # (the default is the longest lifetime the configuration gives one). `consume` is one `SET NX`, so of concurrent
  # callers on any node exactly one wins.
  class RedisTokenStore
    include TokenStore

    alias Payload = Hash(String, InMemoryStore::TokenPayload)

    # Sets the revocation unless it already lives longer (or forever): a revocation is never shortened.
    REVOKE = <<-LUA
      local ttl = redis.call('PTTL', KEYS[1])
      if ttl ~= -1 and ttl < tonumber(ARGV[1]) then
        redis.call('SET', KEYS[1], '1', 'PX', ARGV[1])
      end
      return 1
      LUA

    def initialize(@redis : RedisConnection, @revocation_ttl : Time::Span? = nil, @token_ttl : Time::Span? = nil)
    end

    def store(token_id : String, payload)
      key = @redis.key("token", token_id)
      ttl = payload_ttl(payload)
      @redis.run { |redis| ttl ? redis.set(key, payload.to_json, px: ttl) : redis.del(key) }
    end

    def fetch(token_id : String)
      raw = @redis.run(&.get(@redis.key("token", token_id)))
      raise Error.invalid_token unless raw
      decode(raw)
    end

    def revoke(token_id : String)
      revoke(token_id, revocation_ttl)
    end

    def revoke(token_id : String, ttl : Time::Span)
      @redis.run(&.eval(REVOKE, [@redis.key("revoked", token_id)], [RedisConnection.milliseconds(ttl)]))
    end

    def revoked?(token_id : String) : Bool
      @redis.run(&.exists(@redis.key("revoked", token_id))) == 1
    end

    def valid?(token_id : String) : Bool
      !revoked?(token_id)
    end

    def consume(token_id : String) : Bool
      consume(token_id, revocation_ttl)
    end

    def consume(token_id : String, ttl : Time::Span) : Bool
      key = @redis.key("revoked", token_id)
      @redis.run(&.set(key, "1", px: RedisConnection.milliseconds(ttl), nx: true)) == "OK"
    end

    # Milliseconds until the payload's `exp`, nil once it has passed.
    private def payload_ttl(payload) : Int64?
      exp = payload["exp"]?
      return RedisConnection.milliseconds(token_ttl) unless exp.is_a?(Int64)
      left = Time.unix(exp) - Time.utc
      RedisConnection.milliseconds(left) if left.positive?
    end

    private def decode(raw : String) : Payload
      payload = Payload.new
      JSON.parse(raw).as_h.each { |name, value| payload[name] = value.raw.as(InMemoryStore::TokenPayload) }
      payload
    rescue JSON::ParseException | TypeCastError
      raise Error.invalid_token
    end

    private def revocation_ttl : Time::Span
      @revocation_ttl || longest_lifetime
    end

    private def token_ttl : Time::Span
      @token_ttl || longest_lifetime
    end

    private def longest_lifetime : Time::Span
      config = Authly.config
      {config.refresh_absolute_ttl, config.refresh_ttl, config.access_ttl}.max
    end
  end
end
