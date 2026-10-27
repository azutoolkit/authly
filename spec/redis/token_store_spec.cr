require "../spec_helper"
require "../support/redis"
require "../../src/conformance"

redis_conformance("RedisTokenStore") do
  Authly::Stores::Conformance.token_store("RedisTokenStore") { Authly::RedisTokenStore.new(RedisSpec.connection) }
end

private def token_store : Authly::RedisTokenStore
  Authly::RedisTokenStore.new(RedisSpec.connection)
end

private def payload(**values) : Hash(String, Authly::InMemoryStore::TokenPayload)
  values.to_h.transform_keys(&.to_s).transform_values(&.as(Authly::InMemoryStore::TokenPayload))
end

describe Authly::RedisTokenStore do
  it "fails closed: every operation raises StoreUnavailable when Redis cannot be reached" do
    store = Authly::RedisTokenStore.new(Authly::RedisConnection.new(url: "redis://127.0.0.1:1"))

    expect_raises(Authly::StoreUnavailable) { store.revoked?("t") }
    expect_raises(Authly::StoreUnavailable) { store.consume("t") }
    expect_raises(Authly::StoreUnavailable) { store.fetch("t") }
    expect_raises(Authly::StoreUnavailable) { store.revoke("t", 1.minute) }
  end
end
