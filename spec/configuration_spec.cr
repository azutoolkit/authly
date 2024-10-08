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

  describe Authly::SecurityConfiguration do
    it "generates default secret and public keys" do
      security_config = Authly::Configuration.instance.security
      security_config.secret_key.should_not be_nil
      security_config.public_key.should_not be_nil
    end

    it "uses HS256 as default algorithm" do
      security_config = Authly::Configuration.instance.security
      security_config.algorithm.should eq(JWT::Algorithm::HS256)
    end
  end

  describe Authly::TTLConfiguration do
    it "sets default TTL values" do
      ttl_config = Authly::Configuration.instance.ttl
      ttl_config.refresh_ttl.should eq(1.day)
      ttl_config.code_ttl.should eq(5.minutes)
      ttl_config.access_ttl.should eq(1.hour)
    end
  end

  describe Authly::ProvidersConfiguration do
    it "creates default owners and clients" do
      provider_config = Authly::Configuration.instance.owner_client
      provider_config.owners.should_not be_nil
      provider_config.clients.should_not be_nil
    end

    it "sets a default JTI provider" do
      provider_config = Authly::Configuration.instance.owner_client
      provider_config.jti_provider.should be_a(Authly::InMemoryJTIProvider)
    end
  end
end
