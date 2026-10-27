module Authly::Stores
  module Conformance
    alias Payload = Hash(String, String | Int64 | Bool | Float64)

    # The `TokenStore` contract: unknown tokens raise `Authly::Error`, payload values keep their types, and of several
    # concurrent `consume`s of one id exactly one wins.
    def self.token_store(name : String, &factory : -> TokenStore)
      describe "#{name} (TokenStore conformance)" do
        it "raises Authly::Error for a token it does not know" do
          expect_raises(Authly::Error) { factory.call.fetch(random_id) }
        end

        it "returns the payload it stored, with the value types" do
          store, id = factory.call, random_id
          payload = Payload{"cid" => "client", "exp" => 1.hour.from_now.to_unix, "admin" => true, "score" => 1.5}
          store.store(id, payload)

          store.fetch(id).should eq payload
        end

        it "replaces the payload of a token stored again" do
          store, id = factory.call, random_id
          store.store(id, Payload{"cid" => "first", "exp" => 1.hour.from_now.to_unix})
          store.store(id, Payload{"cid" => "second", "exp" => 1.hour.from_now.to_unix})

          store.fetch(id)["cid"].should eq "second"
        end

        it "reports a revoked token as revoked and not valid, and others as valid" do
          store, id = factory.call, random_id
          store.revoke(id)

          store.revoked?(id).should be_true
          store.valid?(id).should be_false
          store.revoked?(random_id).should be_false
          store.valid?(random_id).should be_true
        end

        it "revokes for a TTL" do
          store, id = factory.call, random_id
          store.revoke(id, 1.hour)

          store.revoked?(id).should be_true
        end

        it "lets an id be consumed once, and then counts it as revoked" do
          store, id, other = factory.call, random_id, random_id

          store.consume(id).should be_true
          store.consume(id).should be_false
          store.revoked?(id).should be_true
          store.consume(other, 1.hour).should be_true
          store.consume(other, 1.hour).should be_false
        end

        it "does not let a revoked id be consumed" do
          store, id = factory.call, random_id
          store.revoke(id)

          store.consume(id).should be_false
        end

        it "lets exactly one of many concurrent consumers win" do
          store, id = factory.call, random_id

          concurrently(20) { store.consume(id, 1.hour) }.count(true).should eq 1
        end
      end
    end
  end
end
