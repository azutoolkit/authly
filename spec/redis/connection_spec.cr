require "../spec_helper"
require "../support/redis"

describe Authly::RedisConnection do
  it "keys an id by its SHA-256 under the prefix, so no credential is readable from a key" do
    connection = Authly::RedisConnection.new(url: RedisSpec::URL, prefix: "app:")
    key = connection.key("token", "s3cr3t-token")

    key.should eq "app:token:#{Digest::SHA256.hexdigest("s3cr3t-token")}"
    key.should_not contain "s3cr3t-token"
  end

  it "uses the authly: prefix by default" do
    Authly::RedisConnection.new(url: RedisSpec::URL).key("state", "x").should start_with "authly:state:"
  end

  it "does not connect until it is used" do
    Authly::RedisConnection.new(url: "redis://127.0.0.1:1")
  end

  it "reports a server it cannot reach as StoreUnavailable, naming no key" do
    connection = Authly::RedisConnection.new(url: "redis://127.0.0.1:1", prefix: "app:")

    error = expect_raises(Authly::StoreUnavailable) { connection.run(&.get(connection.key("token", "s3cr3t-token"))) }
    error.message.to_s.should_not contain "s3cr3t-token"
    error.message.to_s.should_not contain Digest::SHA256.hexdigest("s3cr3t-token")
  end

  redis_it "runs commands on the server" do
    RedisSpec.connection.run(&.ping).should eq "PONG"
  end
end
