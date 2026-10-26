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

  it "can be replaced by the host" do
    limiter = Authly::InMemoryAttemptLimiter.new
    Authly.config.attempt_limiter.should be_a Authly::AttemptLimiter
    previous = Authly.config.attempt_limiter
    Authly.config.attempt_limiter = limiter
    Authly.config.attempt_limiter.should be limiter
    Authly.config.attempt_limiter = previous
  end
end
