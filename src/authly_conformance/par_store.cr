module Authly::Stores
  module Conformance
    # The `PARStore` contract: a pushed request is read back until it expires and redeemed by exactly one caller.
    def self.par_store(name : String, &factory : -> PARStore)
      describe "#{name} (PARStore conformance)" do
        it "returns the request it stored" do
          store, uri = factory.call, "urn:ietf:params:oauth:request_uri:#{random_id}"
          store.store(uri, {"scope" => "read", "state" => "xyz"}, "client", 1.minute)

          data = store.fetch(uri).should_not be_nil
          data.params.should eq({"scope" => "read", "state" => "xyz"})
          data.client_id.should eq "client"
          data.expires_at.should be_close(1.minute.from_now, 5.seconds)
          store.valid?(uri).should be_true
        end

        it "returns nothing for a request it does not know" do
          store = factory.call
          store.fetch(random_id).should be_nil
          store.valid?(random_id).should be_false
          store.consume(random_id).should be_false
        end

        it "redeems a request once" do
          store, uri = factory.call, random_id
          store.store(uri, {"scope" => "read"}, "client", 1.minute)

          store.consume(uri).should be_true
          store.consume(uri).should be_false
          store.fetch(uri).should be_nil
        end

        it "forgets a request once its TTL has passed" do
          store, uri = factory.call, random_id
          store.store(uri, {"scope" => "read"}, "client", 50.milliseconds)
          sleep 120.milliseconds

          store.fetch(uri).should be_nil
          store.valid?(uri).should be_false
          store.consume(uri).should be_false
        end

        it "lets exactly one of many concurrent redeemers win" do
          store, uri = factory.call, random_id
          store.store(uri, {"scope" => "read"}, "client", 1.minute)

          concurrently(20) { store.consume(uri) }.count(true).should eq 1
        end
      end
    end
  end
end
