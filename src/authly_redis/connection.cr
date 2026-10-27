module Authly
  # The pool, key prefix and error handling that the Redis stores share. Pass one connection to every store:
  #
  # ```
  # redis = Authly::RedisConnection.new(url: ENV["REDIS_URL"], prefix: "myapp:authly:")
  # Authly.config.token_store = Authly::RedisTokenStore.new(redis)
  # ```
  #
  # Every key is `<prefix><kind>:<SHA-256 of the id>`, so neither a token nor a code can be read from a key (in
  # `MONITOR`, `SLOWLOG` or a key listing). Any failure to talk to the server raises `StoreUnavailable`, naming the
  # error class only: Authly then refuses (503 or an error), it never treats an outage as "not revoked".
  class RedisConnection
    getter prefix : String

    def initialize(@client : ::Redis::PooledClient, @prefix : String = "authly:")
    end

    # Connections open lazily, at most *pool_size*; a command waits *pool_timeout* seconds for a free one.
    def self.new(url : String = ENV["REDIS_URL"]? || "redis://127.0.0.1:6379", prefix : String = "authly:",
                 pool_size : Int32 = 5, pool_timeout : Float64 = 5.0,
                 connect_timeout : Time::Span = 2.seconds, command_timeout : Time::Span = 2.seconds)
      client = ::Redis::PooledClient.new(url: url, pool_size: pool_size, pool_timeout: pool_timeout,
        connect_timeout: connect_timeout, command_timeout: command_timeout)
      new(client, prefix)
    end

    def key(kind : String, id : String) : String
      "#{@prefix}#{kind}:#{Digest::SHA256.hexdigest(id)}"
    end

    # A TTL in whole milliseconds for `PX`, at least 1 (Redis refuses 0).
    def self.milliseconds(span : Time::Span) : Int64
      {span.total_milliseconds.ceil.to_i64, 1_i64}.max
    end

    def run(& : ::Redis::PooledClient -> T) : T forall T
      yield @client
    rescue e : ::Redis::Error | IO::Error | OpenSSL::Error
      raise StoreUnavailable.new("Redis unavailable (#{e.class})")
    end
  end
end
