module Authly
  # A `PARStore` in Redis: the request lives for its TTL, and `consume` is one `DEL`, so a `request_uri` is redeemed
  # by exactly one caller on any node.
  class RedisPARStore
    include PARStore

    private struct Record
      include JSON::Serializable

      getter params : Hash(String, String)
      getter client_id : String
      getter expires_at_ms : Int64

      def initialize(@params, @client_id, @expires_at_ms)
      end
    end

    def initialize(@redis : RedisConnection)
    end

    def store(request_uri : String, params : Hash(String, String), client_id : String, ttl : Time::Span = 90.seconds)
      record = Record.new(params, client_id, (Time.utc + ttl).to_unix_ms)
      @redis.run(&.set(@redis.key("par", request_uri), record.to_json, px: RedisConnection.milliseconds(ttl)))
    end

    def fetch(request_uri : String) : PARData?
      raw = @redis.run(&.get(@redis.key("par", request_uri)))
      return unless raw
      record = Record.from_json(raw)
      data = PARData.new(record.params, record.client_id, Time.unix_ms(record.expires_at_ms))
      data unless data.expired?
    end

    def consume(request_uri : String) : Bool
      @redis.run(&.del(@redis.key("par", request_uri))) == 1
    end

    def valid?(request_uri : String) : Bool
      @redis.run(&.exists(@redis.key("par", request_uri))) == 1
    end
  end
end
