require "../spec_helper"
require "../support/redis"
require "../../src/conformance"

redis_conformance("RedisStateStore") do
  Authly::Stores::Conformance.state_store("RedisStateStore") { Authly::RedisStateStore.new(RedisSpec.connection) }
end

describe Authly::RedisStateStore do
  redis_it "keys a nonce by its hash, with the nonce's TTL" do
    state = Random::Secure.hex(16)
    Authly::RedisStateStore.new(RedisSpec.connection).store(state, 10.minutes)

    RedisSpec.pttl("state", state).should be_close(600_000, 5_000)
    RedisSpec.keys.none?(&.includes?(state)).should be_true
  end

  it "fails closed when Redis cannot be reached" do
    store = Authly::RedisStateStore.new(Authly::RedisConnection.new(url: "redis://127.0.0.1:1"))

    expect_raises(Authly::StoreUnavailable) { store.consume("nonce") }
  end
end
