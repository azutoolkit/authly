module Authly::Stores
  module Conformance
    # The `StateStore` contract: a stored nonce is consumed once, before it expires, by exactly one caller.
    def self.state_store(name : String, &factory : -> StateStore)
      describe "#{name} (StateStore conformance)" do
        it "consumes a stored state once" do
          store, state = factory.call, random_id
          store.store(state, 1.minute)

          store.valid?(state).should be_true
          store.consume(state).should be_true
          store.consume(state).should be_false
          store.valid?(state).should be_false
        end

        it "does not consume a state it never stored" do
          factory.call.consume(random_id).should be_false
        end

        it "forgets a state once its TTL has passed" do
          store, state = factory.call, random_id
          store.store(state, 100.milliseconds)
          sleep 300.milliseconds

          store.valid?(state).should be_false
          store.consume(state).should be_false
        end

        it "lets exactly one of many concurrent consumers win" do
          store, state = factory.call, random_id
          store.store(state, 1.minute)

          concurrently(20) { store.consume(state) }.count(true).should eq 1
        end
      end
    end
  end
end
