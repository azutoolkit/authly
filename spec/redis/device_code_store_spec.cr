require "../spec_helper"
require "../support/redis"
require "../../src/conformance"

redis_conformance("RedisDeviceCodeStore") do
  Authly::Stores::Conformance.device_code_store("RedisDeviceCodeStore") { Authly::RedisDeviceCodeStore.new(RedisSpec.connection) }
end

private def redis_device_data(expires_at : Time = Time.unix(10.minutes.from_now.to_unix)) : Authly::DeviceCodeData
  Authly::DeviceCodeData.new(Random::Secure.hex(16), Random::Secure.hex(4).upcase, "client", "read", expires_at)
end

describe Authly::RedisDeviceCodeStore do
  redis_it "keeps both codes until the authorization expires, keyed by their hashes" do
    data = redis_device_data
    Authly::RedisDeviceCodeStore.new(RedisSpec.connection).store(data.device_code, data)

    RedisSpec.pttl("device", data.device_code).should be_close(600_000, 5_000)
    RedisSpec.pttl("user_code", data.user_code).should be_close(600_000, 5_000)
    RedisSpec.keys.none? { |key| key.includes?(data.device_code) || key.includes?(data.user_code) }.should be_true
  end

  redis_it "does not keep the device code in the user code index" do
    data = redis_device_data
    Authly::RedisDeviceCodeStore.new(RedisSpec.connection).store(data.device_code, data)

    index = RedisSpec.connection.run(&.get(RedisSpec.connection.key("user_code", data.user_code)))
    index.to_s.should_not contain data.device_code
  end

  redis_it "does not bring a deleted authorization back on update" do
    store, data = Authly::RedisDeviceCodeStore.new(RedisSpec.connection), redis_device_data
    store.store(data.device_code, data)
    store.delete(data.device_code)
    store.update(data.device_code, data)

    store.fetch(data.device_code).should be_nil
  end

  it "fails closed when Redis cannot be reached" do
    store = Authly::RedisDeviceCodeStore.new(Authly::RedisConnection.new(url: "redis://127.0.0.1:1"))

    expect_raises(Authly::StoreUnavailable) { store.fetch_by_user_code("ABCD") }
  end
end
