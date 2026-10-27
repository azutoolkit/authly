require "../spec_helper"
require "../support/redis"
require "../../src/conformance"

redis_conformance("RedisPARStore") do
  Authly::Stores::Conformance.par_store("RedisPARStore") { Authly::RedisPARStore.new(RedisSpec.connection) }
end

describe Authly::RedisPARStore do
  redis_it "keys a request_uri by its hash, with the request's TTL" do
    uri = "urn:ietf:params:oauth:request_uri:#{Random::Secure.hex(16)}"
    Authly::RedisPARStore.new(RedisSpec.connection).store(uri, {"scope" => "read"}, "client", 90.seconds)

    RedisSpec.pttl("par", uri).should be_close(90_000, 5_000)
    RedisSpec.keys.none?(&.includes?(uri)).should be_true
  end

  it "fails closed when Redis cannot be reached" do
    store = Authly::RedisPARStore.new(Authly::RedisConnection.new(url: "redis://127.0.0.1:1"))

    expect_raises(Authly::StoreUnavailable) { store.consume("urn:x") }
  end
end
