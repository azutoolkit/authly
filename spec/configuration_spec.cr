require "./spec_helper"

describe Authly::Configuration do
  it "creates a singleton instance" do
    instance1 = Authly::Configuration.instance
    instance2 = Authly::Configuration.instance
    instance1.should_not be_nil
    instance1.should eq(instance2)
  end

  it "sets and gets issuer correctly" do
    config = Authly::Configuration.instance
    config.issuer = "New Issuer"
    config.issuer.should eq("New Issuer")
  end

  it "generates default secret and public keys" do
    config = Authly::Configuration.instance
    config.secret_key.should_not be_nil
    config.public_key.should_not be_nil
    config.algorithm.should eq(JWT::Algorithm::HS256)
    config.refresh_ttl.should eq(1.day)
    config.code_ttl.should eq(5.minutes)
    config.access_ttl.should eq(1.hour)
    config.owners.should_not be_nil
    config.clients.should_not be_nil
    config.token_store.should be_a(Authly::InMemoryTokenStore)
  end
end
