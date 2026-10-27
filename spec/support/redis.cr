require "../../src/redis"

# The Redis specs run against `REDIS_URL` (default `redis://127.0.0.1:6379`) and go pending when no server answers.
# Every key they write is under a prefix of their own and has a TTL; the suite also deletes them when it ends.
module RedisSpec
  URL    = ENV["REDIS_URL"]? || "redis://127.0.0.1:6379"
  PREFIX = "authly-spec:#{Random::Secure.hex(4)}:"

  AVAILABLE = begin
    redis = ::Redis.new(url: URL, connect_timeout: 1.second, command_timeout: 1.second)
    (redis.ping == "PONG").tap { redis.close }
  rescue
    false
  end

  def self.connection : Authly::RedisConnection
    @@connection ||= Authly::RedisConnection.new(url: URL, prefix: PREFIX)
  end

  def self.pttl(kind : String, id : String) : Int64
    connection.run(&.pttl(connection.key(kind, id)))
  end

  # Every key the specs wrote, read with SCAN.
  def self.keys : Array(String)
    found = [] of String
    redis = ::Redis.new(url: URL)
    cursor = "0"
    loop do
      cursor, batch = redis.scan(cursor, match: "#{PREFIX}*", count: 500)
      batch.as(Array).each { |key| found << key.to_s }
      break if cursor.to_s == "0"
    end
    redis.close
    found
  end
end

# An example that needs a Redis server: pending without one, so the suite passes where none runs.
def redis_it(description : String, file = __FILE__, line = __LINE__, &block : ->)
  if RedisSpec::AVAILABLE
    it(description, file, line, &block)
  else
    pending("#{description} (no Redis at #{RedisSpec::URL})", file, line) { }
  end
end

# Shared examples that need a Redis server: one pending example without one.
def redis_conformance(name : String, file = __FILE__, line = __LINE__, &)
  if RedisSpec::AVAILABLE
    yield
  else
    pending("#{name} conformance (no Redis at #{RedisSpec::URL})", file, line) { }
  end
end

Spec.after_suite do
  next unless RedisSpec::AVAILABLE
  keys = RedisSpec.keys
  RedisSpec.connection.run(&.del(keys)) unless keys.empty?
end
