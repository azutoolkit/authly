module Authly::Stores
  module Conformance
    # The `ClientStore` contract: registered clients are stored, read back, updated only when they exist, and deleted.
    def self.client_store(name : String, &factory : -> ClientStore)
      describe "#{name} (ClientStore conformance)" do
        it "returns the client it stored" do
          store, client = factory.call, dynamic_client
          store.store(client).should be_true

          stored = store.fetch(client.client_id).should_not be_nil
          stored.to_json.should eq client.to_json
        end

        it "returns nothing for a client it does not know" do
          factory.call.fetch(random_id).should be_nil
        end

        it "updates a stored client only" do
          store, client = factory.call, dynamic_client
          store.update(client).should be_false
          store.store(client)
          renamed = dynamic_client(client.client_id, "renamed")

          store.update(renamed).should be_true
          store.fetch(client.client_id).try(&.client_name).should eq "renamed"
        end

        it "deletes a client once" do
          store, client = factory.call, dynamic_client
          store.store(client)

          store.delete(client.client_id).should be_true
          store.delete(client.client_id).should be_false
          store.fetch(client.client_id).should be_nil
        end
      end
    end

    private def self.dynamic_client(client_id : String = random_id, name : String = "app") : DynamicClient
      DynamicClient.new(client_id, random_id, ["https://app.example/callback"], client_name: name)
    end
  end
end
