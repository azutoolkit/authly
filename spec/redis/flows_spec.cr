require "../spec_helper"
require "../support/redis"

# Authly's own flows with every store in Redis; a second connection stands for a second node.
module RedisFlowSpec
  def self.use_redis(connection = RedisSpec.connection) : Nil
    config = Authly.config
    config.token_store = Authly::RedisTokenStore.new(connection)
    config.state_store = Authly::RedisStateStore.new(connection)
    config.device_code_store = Authly::RedisDeviceCodeStore.new(connection)
    config.attempt_limiter = Authly::RedisAttemptLimiter.new(connection)
  end

  def self.other_node : Authly::RedisConnection
    Authly::RedisConnection.new(url: RedisSpec::URL, prefix: RedisSpec::PREFIX)
  end

  def self.poll(data : Authly::DeviceCodeData) : Authly::AccessToken
    Authly.access_token("urn:ietf:params:oauth:grant-type:device_code", client_id: "1", client_secret: "", device_code: data.device_code)
  end
end

describe "Authly with Redis stores" do
  redis_it "honours on one node a JWT revoked on another" do
    RedisFlowSpec.use_redis
    token = Authly::AccessToken.new("test_client", "read", subject: "alice").access_token
    Authly.revoke(token)
    RedisFlowSpec.use_redis(RedisFlowSpec.other_node)

    Authly::StrategyTokenVerifier.new.verify(token).should be_nil
  end

  redis_it "redeems a device code approved on another node exactly once" do
    RedisFlowSpec.use_redis
    data = Authly::DeviceCode.create_device_authorization("1", "read")
    RedisFlowSpec.use_redis(RedisFlowSpec.other_node)
    AuthorizationSecuritySpec.device_submit(data.user_code, "approve").status.should eq 200

    RedisFlowSpec.poll(data).access_token.should_not be_empty
    expect_raises(Authly::Error) { RedisFlowSpec.poll(data) }
  end

  it "fails closed: a bearer token cannot be verified while Redis is down" do
    token = Authly::AccessToken.new("test_client", "read", subject: "alice").access_token
    RedisFlowSpec.use_redis(Authly::RedisConnection.new(url: "redis://127.0.0.1:1"))

    expect_raises(Authly::VerificationUnavailable) { Authly::StrategyTokenVerifier.new.verify(token) }
  end
end
