module Authly
  # A `ClientStore` in Redis. A registered client is a durable record, so it has no TTL: run Redis with persistence
  # (AOF or RDB) and `maxmemory-policy noeviction`, or keep clients in your database instead. Registration is
  # throttled by `registration_limiter`, which bounds how fast the set can grow.
  class RedisClientStore
    include ClientStore

    def initialize(@redis : RedisConnection)
    end

    def store(client : DynamicClient) : Bool
      @redis.run(&.set(key(client.client_id), client.to_json)) == "OK"
    end

    def fetch(client_id : String) : DynamicClient?
      raw = @redis.run(&.get(key(client_id)))
      DynamicClient.from_json(raw) if raw
    end

    def delete(client_id : String) : Bool
      @redis.run(&.del(key(client_id))) == 1
    end

    def update(client : DynamicClient) : Bool
      @redis.run(&.set(key(client.client_id), client.to_json, xx: true)) == "OK"
    end

    private def key(client_id : String) : String
      @redis.key("client", client_id)
    end
  end
end
