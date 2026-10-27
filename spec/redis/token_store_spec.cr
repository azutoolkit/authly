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
  redis_it "keeps a payload until its exp" do
    id = Random::Secure.hex(16)
    token_store.store(id, payload(exp: 1.hour.from_now.to_unix))

    RedisSpec.pttl("token", id).should be_close(3_600_000, 5_000)
  end

  redis_it "keeps a payload without exp for the longest lifetime the configuration gives a token" do
    id = Random::Secure.hex(16)
    token_store.store(id, payload(cid: "client"))

    RedisSpec.pttl("token", id).should be_close(Authly.config.refresh_absolute_ttl.total_milliseconds, 5_000)
  end

  redis_it "drops a payload whose exp has passed" do
    store, id = token_store, Random::Secure.hex(16)
    store.store(id, payload(exp: 1.hour.from_now.to_unix))
    store.store(id, payload(exp: 1.minute.ago.to_unix))

    expect_raises(Authly::Error) { store.fetch(id) }
  end

  redis_it "writes no token into a key" do
    id = Random::Secure.hex(16)
    token_store.store(id, payload(exp: 1.hour.from_now.to_unix))
    token_store.revoke(id)

    RedisSpec.keys.should_not be_empty
    RedisSpec.keys.none?(&.includes?(id)).should be_true
  end

  redis_it "never shortens a revocation" do
    id = Random::Secure.hex(16)
    token_store.revoke(id, 1.hour)
    token_store.revoke(id, 1.second)

    RedisSpec.pttl("revoked", id).should be > 3_000_000
  end

  redis_it "forgets a revocation and a claim once their TTL has passed" do
    store, id, claimed = token_store, Random::Secure.hex(16), Random::Secure.hex(16)
    store.revoke(id)
    RedisSpec.pttl("revoked", id).should be > 0
    store.revoke(id, 50.milliseconds) # longer revocations stay
    store.consume(claimed, 50.milliseconds)
    sleep 120.milliseconds

    store.revoked?(id).should be_true
    store.consume(claimed, 50.milliseconds).should be_true
  end

  redis_it "lets exactly one of many fibers on separate connections claim an id" do
    store = Authly::RedisTokenStore.new(Authly::RedisConnection.new(url: RedisSpec::URL, prefix: RedisSpec::PREFIX, pool_size: 10))
    id = Random::Secure.hex(16)

    Authly::Stores::Conformance.concurrently(100) { store.consume(id, 1.minute) }.count(true).should eq 1
  end

  it "fails closed: every operation raises StoreUnavailable when Redis cannot be reached" do
    store = Authly::RedisTokenStore.new(Authly::RedisConnection.new(url: "redis://127.0.0.1:1"))

    expect_raises(Authly::StoreUnavailable) { store.revoked?("t") }
    expect_raises(Authly::StoreUnavailable) { store.consume("t") }
    expect_raises(Authly::StoreUnavailable) { store.fetch("t") }
    expect_raises(Authly::StoreUnavailable) { store.revoke("t", 1.minute) }
  end
end
