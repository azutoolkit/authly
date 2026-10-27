module Authly
  # A `StateStore` in Redis: a nonce is a key with the nonce's TTL, and `consume` is one `DEL`, so of concurrent
  # callers on any node exactly one wins.
  class RedisStateStore
    include StateStore

    def initialize(@redis : RedisConnection)
    end

    def store(state : String, ttl : Time::Span = 5.minutes)
      @redis.run(&.set(@redis.key("state", state), "1", px: RedisConnection.milliseconds(ttl)))
    end

    def valid?(state : String) : Bool
      @redis.run(&.exists(@redis.key("state", state))) == 1
    end

    def consume(state : String) : Bool
      @redis.run(&.del(@redis.key("state", state))) == 1
    end
  end
end
