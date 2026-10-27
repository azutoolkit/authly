module Authly::Stores
  module Conformance
    # The `AttemptLimiter` contract: `increment` counts atomically within a window that starts with the first event.
    def self.attempt_limiter(name : String, &factory : -> AttemptLimiter)
      describe "#{name} (AttemptLimiter conformance)" do
        it "counts the events of a key and reports it once it reaches the limit" do
          limiter, key = factory.call, random_id

          limiter.exceeded?(key, 2).should be_false
          limiter.increment(key, 1.minute).should eq 1
          limiter.exceeded?(key, 2).should be_false
          limiter.increment(key, 1.minute).should eq 2
          limiter.exceeded?(key, 2).should be_true
        end

        it "counts every key on its own" do
          limiter, key = factory.call, random_id
          limiter.increment(key, 1.minute)

          limiter.increment(random_id, 1.minute).should eq 1
        end

        it "forgets the count once the window has passed" do
          limiter, key = factory.call, random_id
          2.times { limiter.increment(key, 100.milliseconds) }
          sleep 300.milliseconds

          limiter.exceeded?(key, 2).should be_false
          limiter.increment(key, 50.milliseconds).should eq 1
        end

        it "counts concurrent events exactly" do
          limiter, key = factory.call, random_id

          concurrently(20) { limiter.increment(key, 1.minute) }.sort.should eq (1..20).to_a
        end
      end
    end
  end
end
