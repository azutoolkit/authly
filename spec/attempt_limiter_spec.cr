require "./spec_helper"

describe Authly::InMemoryAttemptLimiter do
  it "is not exceeded before the limit and is from the limit on" do
    limiter = Authly::InMemoryAttemptLimiter.new
    2.times { limiter.record("k", 1.minute) }
    limiter.exceeded?("k", 3).should be_false
    limiter.record("k", 1.minute)
    limiter.exceeded?("k", 3).should be_true
    limiter.exceeded?("other", 3).should be_false
  end

  it "forgets a key when its window has passed" do
    limiter = Authly::InMemoryAttemptLimiter.new
    limiter.record("k", 20.milliseconds)
    limiter.exceeded?("k", 1).should be_true
    sleep 40.milliseconds
    limiter.exceeded?("k", 1).should be_false
    limiter.record("k", 1.minute)
    limiter.exceeded?("k", 2).should be_false
  end

  it "does not stretch the window with every event" do
    limiter = Authly::InMemoryAttemptLimiter.new
    limiter.record("k", 30.milliseconds)
    sleep 20.milliseconds
    limiter.record("k", 30.milliseconds)
    sleep 20.milliseconds
    limiter.exceeded?("k", 1).should be_false
  end

  it "never keeps more keys than MAX_ENTRIES" do
    limiter = Authly::InMemoryAttemptLimiter.new
    (Authly::InMemoryAttemptLimiter::MAX_ENTRIES + 500).times { |i| limiter.record("k#{i}", 1.minute) }
    limiter.size.should eq Authly::InMemoryAttemptLimiter::MAX_ENTRIES
  end

  it "sweeps expired keys as it is written to" do
    limiter = Authly::InMemoryAttemptLimiter.new
    400.times { |i| limiter.record("old#{i}", 1.millisecond) }
    sleep 5.milliseconds
    128.times { |i| limiter.record("new#{i}", 1.minute) }
    limiter.size.should be < 200
  end

  describe "#increment" do
    it "counts one event and answers the count within the window" do
      limiter = Authly::InMemoryAttemptLimiter.new
      Array.new(3) { limiter.increment("k", 1.minute) }.should eq [1, 2, 3]
      limiter.increment("other", 1.minute).should eq 1
      limiter.exceeded?("k", 3).should be_true
    end

    it "starts a new window once the old one has passed" do
      limiter = Authly::InMemoryAttemptLimiter.new
      limiter.increment("k", 20.milliseconds).should eq 1
      sleep 40.milliseconds
      limiter.increment("k", 1.minute).should eq 1
    end

    it "hands every concurrent caller a different count" do
      limiter = Authly::InMemoryAttemptLimiter.new
      counts = Channel(Int32).new
      50.times { spawn { counts.send(limiter.increment("k", 1.minute)) } }
      Array.new(50) { counts.receive }.sort.should eq (1..50).to_a
    end
  end

  describe "when it holds MAX_ENTRIES keys" do
    it "makes room by sweeping the expired ones first" do
      limiter = Authly::InMemoryAttemptLimiter.new
      Authly::InMemoryAttemptLimiter::MAX_ENTRIES.times { |i| limiter.increment("old#{i}", 1.millisecond) }
      sleep 5.milliseconds

      limiter.increment("fresh", 1.minute).should eq 1
      limiter.size.should be < Authly::InMemoryAttemptLimiter::MAX_ENTRIES
    end

    it "keeps a live counter that is at its limit instead of dropping it for a new key" do
      limiter = Authly::InMemoryAttemptLimiter.new
      3.times { limiter.increment("attacker", 1.minute) }
      (Authly::InMemoryAttemptLimiter::MAX_ENTRIES - 1).times { |i| limiter.increment("live#{i}", 1.minute) }

      limiter.increment("newcomer", 1.minute)
      limiter.exceeded?("attacker", 3).should be_true
      limiter.size.should eq Authly::InMemoryAttemptLimiter::MAX_ENTRIES
    end

    it "fails closed for a new key when every entry is live" do
      limiter = Authly::InMemoryAttemptLimiter.new
      Authly::InMemoryAttemptLimiter::MAX_ENTRIES.times { |i| limiter.increment("live#{i}", 1.minute) }

      limiter.increment("newcomer", 1.minute).should be > 1_000_000
      limiter.size.should eq Authly::InMemoryAttemptLimiter::MAX_ENTRIES
    end

    it "still counts a key it already holds" do
      limiter = Authly::InMemoryAttemptLimiter.new
      Authly::InMemoryAttemptLimiter::MAX_ENTRIES.times { |i| limiter.increment("live#{i}", 1.minute) }
      limiter.increment("live0", 1.minute).should eq 2
    end
  end

  it "can be replaced by the host" do
    limiter = Authly::InMemoryAttemptLimiter.new
    Authly.config.attempt_limiter.should be_a Authly::AttemptLimiter
    previous = Authly.config.attempt_limiter
    Authly.config.attempt_limiter = limiter
    Authly.config.attempt_limiter.should be limiter
    Authly.config.attempt_limiter = previous
  end
end
