module Authly::Stores
  module Conformance
    # The `DeviceCodeStore` contract: an authorization is found by device code and by user code until it expires.
    def self.device_code_store(name : String, &factory : -> DeviceCodeStore)
      describe "#{name} (DeviceCodeStore conformance)" do
        it "returns what it stored, by device code and by user code" do
          store, data = factory.call, device_data
          store.store(data.device_code, data)

          store.fetch(data.device_code).should eq data
          store.fetch_by_user_code(data.user_code).should eq data
        end

        it "returns nothing for codes it does not know" do
          store = factory.call
          store.fetch(random_id).should be_nil
          store.fetch_by_user_code(random_id).should be_nil
        end

        it "keeps an update" do
          store, data = factory.call, device_data
          store.store(data.device_code, data)
          data.verified = true
          data.user_id = "owner"
          data.last_polled_at = Time.utc(2030, 1, 1)
          store.update(data.device_code, data)

          store.fetch(data.device_code).should eq data
          store.fetch_by_user_code(data.user_code).should eq data
        end

        it "forgets a deleted authorization under both codes" do
          store, data = factory.call, device_data
          store.store(data.device_code, data)
          store.delete(data.device_code)

          store.fetch(data.device_code).should be_nil
          store.fetch_by_user_code(data.user_code).should be_nil
        end

        it "does not return an expired authorization" do
          store, data = factory.call, device_data(1.second)
          store.store(data.device_code, data)
          sleep 1100.milliseconds

          store.fetch(data.device_code).should be_nil
          store.fetch_by_user_code(data.user_code).should be_nil
        end
      end
    end

    private def self.device_data(lifetime : Time::Span = 10.minutes) : DeviceCodeData
      # Whole seconds, as `DeviceCodeData` serializes times: at most *lifetime* from now.
      DeviceCodeData.new(random_id, random_id[0, 8].upcase, "client", "read", Time.unix((Time.utc + lifetime).to_unix))
    end
  end
end
