require "./spec_helper"

module Authly
  describe InMemoryStateStore do
    it "stores and validates state" do
      store = InMemoryStateStore.new
      state = "test_state_#{Random::Secure.hex(16)}"

      store.store(state)
      store.valid?(state).should be_true
    end

    it "returns false for non-existent state" do
      store = InMemoryStateStore.new
      store.valid?("non_existent_state").should be_false
    end

    it "consumes state after use" do
      store = InMemoryStateStore.new
      state = "test_state_#{Random::Secure.hex(16)}"

      store.store(state)
      store.valid?(state).should be_true

      store.consume(state)
      store.valid?(state).should be_false
    end

    it "expires state after TTL" do
      store = InMemoryStateStore.new
      state = "test_state_#{Random::Secure.hex(16)}"

      # Store with very short TTL
      store.store(state, 0.seconds)

      # Should be expired immediately
      store.valid?(state).should be_false
    end

    it "cleans up expired states" do
      store = InMemoryStateStore.new
      state1 = "state1_#{Random::Secure.hex(16)}"
      state2 = "state2_#{Random::Secure.hex(16)}"

      # Store one expired, one valid
      store.store(state1, 0.seconds)
      store.store(state2, 5.minutes)

      store.cleanup_expired

      store.valid?(state1).should be_false
      store.valid?(state2).should be_true
    end

    it "prevents replay attacks" do
      store = InMemoryStateStore.new
      state = "test_state_#{Random::Secure.hex(16)}"

      store.store(state)

      # First use should be valid
      store.valid?(state).should be_true
      store.consume(state)

      # Second use should fail (replay attack)
      store.valid?(state).should be_false
    end
  end
end

