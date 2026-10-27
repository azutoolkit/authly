require "../spec_helper"
require "../support/redis"
require "../../src/conformance"

redis_conformance("RedisAttemptLimiter") do
  Authly::Stores::Conformance.attempt_limiter("RedisAttemptLimiter") { Authly::RedisAttemptLimiter.new(RedisSpec.connection) }
end

describe Authly::RedisAttemptLimiter do
  redis_it "keys a counter by its hash and expires it with its window" do
    key = "device:source:203.0.113.7"
    Authly::RedisAttemptLimiter.new(RedisSpec.connection).increment(key, 15.minutes)

    RedisSpec.pttl("attempts", key).should be_close(900_000, 5_000)
    RedisSpec.keys.none?(&.includes?("203.0.113.7")).should be_true
  end

  redis_it "does not extend the window with later events" do
    limiter, key = Authly::RedisAttemptLimiter.new(RedisSpec.connection), Random::Secure.hex(8)
    limiter.increment(key, 1.second)
    limiter.increment(key, 1.hour)

    RedisSpec.pttl("attempts", key).should be <= 1_000
  end

  it "fails closed when Redis cannot be reached" do
    limiter = Authly::RedisAttemptLimiter.new(Authly::RedisConnection.new(url: "redis://127.0.0.1:1"))

    expect_raises(Authly::StoreUnavailable) { limiter.increment("key", 1.minute) }
  end
end
