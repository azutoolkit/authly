require "../spec_helper"

module DeviceSpec
  WRONG = "ABCD-EFGH"

  def self.fresh(&)
    source = Authly.config.attempt_source
    Authly.config.device_code_store = Authly::InMemoryDeviceCodeStore.new
    Authly.config.token_store = Authly::InMemoryStore.new
    Authly.config.attempt_limiter = Authly::InMemoryAttemptLimiter.new
    yield
  ensure
    Authly.config.attempt_source = source.not_nil!
  end

  def self.poll(data : Authly::DeviceCodeData, client = "1") : Authly::AccessToken
    Authly.access_token("urn:ietf:params:oauth:grant-type:device_code", client_id: client, client_secret: "", device_code: data.device_code)
  end

  def self.rewind_poll_clock(data : Authly::DeviceCodeData)
    stored = Authly.config.device_code_store.fetch(data.device_code).not_nil!
    stored.last_polled_at = 1.hour.ago
    Authly.config.device_code_store.update(data.device_code, stored)
  end

  def self.approve(data : Authly::DeviceCodeData, user = "john")
    AuthorizationSecuritySpec.device_submit(data.user_code, "approve", user)
  end
end

describe "Device flow brute force" do
  it "counts a lookup with one atomic increment per key" do
    DeviceSpec.fresh do
      limiter = IncrementOnlyLimiter.new
      Authly.config.attempt_limiter = limiter
      Authly.config.attempt_source = ->(_ctx : HTTP::Server::Context) { "203.0.113.9".as(String?) }

      AuthorizationSecuritySpec.device_get("/device?user_code=#{DeviceSpec::WRONG}", "mallory").status.should eq 200
      limiter.incremented.should eq ["device:subject:mallory", "device:source:203.0.113.9"]
    end
  end

  it "refuses further attempts of a user who guessed wrong too often, even with the right code" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      guesses = Authly.config.device_attempt_limit
      guesses.times { AuthorizationSecuritySpec.device_submit(DeviceSpec::WRONG, "approve", "mallory").status.should eq 400 }

      probe = DeviceSpec.approve(data, "mallory")
      probe.status.should eq 429
      probe.header("Retry-After").should_not be_nil
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.verified?.should be_false
    end
  end

  it "does not hold other users to someone else's failures" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      Authly.config.device_attempt_limit.times { AuthorizationSecuritySpec.device_submit(DeviceSpec::WRONG, "approve", "mallory") }

      DeviceSpec.approve(data, "alice").status.should eq 200
    end
  end

  it "limits a source that rotates accounts" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      Authly.config.attempt_source = ->(_ctx : HTTP::Server::Context) { "203.0.113.9".as(String?) }
      Authly.config.device_attempt_limit.times { |i| AuthorizationSecuritySpec.device_submit(DeviceSpec::WRONG, "approve", "sock#{i}") }

      DeviceSpec.approve(data, "alice").status.should eq 429
      Authly.config.attempt_source = ->(_ctx : HTTP::Server::Context) { "198.51.100.7".as(String?) }
      DeviceSpec.approve(data, "alice").status.should eq 200
    end
  end

  it "counts a wrong code looked up through the page too" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      Authly.config.device_attempt_limit.times { AuthorizationSecuritySpec.device_get("/device?user_code=#{DeviceSpec::WRONG}", "mallory") }

      AuthorizationSecuritySpec.device_get("/device?user_code=#{data.user_code}", "mallory").status.should eq 429
    end
  end

  it "refuses a malformed code without a lookup, and counts it" do
    DeviceSpec.fresh do
      ["", "ABCD", "ABCD-EFGH-IJKL", "ABCD-0123", "' OR 1=1", "ABCD EFGH"].each do |bad|
        probe = AuthorizationSecuritySpec.device_submit(bad, "approve", "bob")
        probe.status.should eq 400
        probe.body.should contain("Invalid or expired user code")
      end
    end
  end

  it "accepts the code typed without the dash or in lower case" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      typed = data.user_code.delete('-').downcase
      AuthorizationSecuritySpec.device_submit(typed, "approve", "carol").status.should eq 200
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.verified?.should be_true
    end
  end
end

describe "Device flow polling" do
  it "answers slow_down to a client polling inside the interval and widens it" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      expect_raises(Authly::Error, Authly::ERROR_MSG[:authorization_pending]) { DeviceSpec.poll(data) }
      expect_raises(Authly::Error, Authly::ERROR_MSG[:slow_down]) { DeviceSpec.poll(data) }
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.interval.should eq data.interval + 5
    end
  end

  it "lets a client that waited poll again" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      expect_raises(Authly::Error, Authly::ERROR_MSG[:authorization_pending]) { DeviceSpec.poll(data) }
      DeviceSpec.rewind_poll_clock(data)
      expect_raises(Authly::Error, Authly::ERROR_MSG[:authorization_pending]) { DeviceSpec.poll(data) }
    end
  end

  it "does not let another client move the polling clock of a device code" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      expect_raises(Authly::Error, Authly::ERROR_MSG[:invalid_grant]) { DeviceSpec.poll(data, "test_client") }
      expect_raises(Authly::Error, Authly::ERROR_MSG[:authorization_pending]) { DeviceSpec.poll(data) }
    end
  end
end

describe "Device flow approval" do
  it "issues a token once per approval" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      DeviceSpec.approve(data)
      DeviceSpec.poll(data).access_token.should_not be_empty

      expect_raises(Authly::Error, Authly::ERROR_MSG[:invalid_grant]) { DeviceSpec.poll(data) }
    end
  end

  it "issues the token to the owner who approved" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      DeviceSpec.approve(data, "john")
      # The same subject an authorization code redeemed for this owner would give
      DeviceSpec.poll(data).sub.should eq Authly.owners.id_token("john")["sub"].to_s
    end
  end

  it "answers access_denied to a device whose owner denied (RFC 8628 3.5), until the code expires" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      AuthorizationSecuritySpec.device_submit(data.user_code, "deny", "john").status.should eq 200
      expect_raises(Authly::Error, Authly::ERROR_MSG[:access_denied]) { DeviceSpec.poll(data) }

      DeviceSpec.rewind_poll_clock(data)
      expect_raises(Authly::Error, Authly::ERROR_MSG[:access_denied]) { DeviceSpec.poll(data) }
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.denied?.should be_true
    end
  end

  it "does not let a second owner approve a code that is already approved" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      DeviceSpec.approve(data, "john").status.should eq 200

      DeviceSpec.approve(data, "mallory").status.should eq 400
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.user_id.should eq "john"
    end
  end

  it "does not let an approved code be denied" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      DeviceSpec.approve(data, "john")

      AuthorizationSecuritySpec.device_submit(data.user_code, "deny", "john").status.should eq 400
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.verified?.should be_true
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.denied?.should be_false
    end
  end

  it "does not let a denied code be approved" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      AuthorizationSecuritySpec.device_submit(data.user_code, "deny", "john")

      DeviceSpec.approve(data, "john").status.should eq 400
      Authly.config.device_code_store.fetch(data.device_code).not_nil!.verified?.should be_false
    end
  end

  it "refuses a device code that expired" do
    DeviceSpec.fresh do
      data = Authly::DeviceCode.create_device_authorization("1", "read")
      data.expires_at = 1.minute.ago
      Authly.config.device_code_store.store(data.device_code, data)
      AuthorizationSecuritySpec.device_submit(data.user_code, "approve", "john").status.should eq 400
      expect_raises(Authly::Error) { DeviceSpec.poll(data) }
    end
  end
end
