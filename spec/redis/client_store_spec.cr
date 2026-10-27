require "../spec_helper"
require "../support/redis"
require "../../src/conformance"

redis_conformance("RedisClientStore") do
  Authly::Stores::Conformance.client_store("RedisClientStore") { Authly::RedisClientStore.new(RedisSpec.connection) }
end

describe Authly::RedisClientStore do
  it "fails closed when Redis cannot be reached" do
    store = Authly::RedisClientStore.new(Authly::RedisConnection.new(url: "redis://127.0.0.1:1"))

    expect_raises(Authly::StoreUnavailable) { store.fetch("client") }
  end
end
