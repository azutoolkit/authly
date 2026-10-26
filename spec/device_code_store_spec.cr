require "./spec_helper"

def device_data_for(code : String, expires_at : Time = 15.minutes.from_now) : Authly::DeviceCodeData
  Authly::DeviceCodeData.new(code, "UC-#{code}", "1", "read", expires_at)
end

describe Authly::InMemoryDeviceCodeStore do
  it "never keeps more than MAX_ENTRIES authorizations" do
    store = Authly::InMemoryDeviceCodeStore.new
    (Authly::InMemoryDeviceCodeStore::MAX_ENTRIES + 100).times { |i| store.store("d#{i}", device_data_for("d#{i}")) }
    store.size.should eq Authly::InMemoryDeviceCodeStore::MAX_ENTRIES
    store.fetch("d0").should be_nil
    store.fetch_by_user_code("UC-d0").should be_nil
    store.fetch("d#{Authly::InMemoryDeviceCodeStore::MAX_ENTRIES + 99}").should_not be_nil
  end

  it "sweeps expired authorizations as it is written to, with their user codes" do
    store = Authly::InMemoryDeviceCodeStore.new
    400.times { |i| store.store("old#{i}", device_data_for("old#{i}", 1.minute.ago)) }
    64.times { |i| store.store("new#{i}", device_data_for("new#{i}")) }
    store.size.should be < 200
    store.fetch_by_user_code("UC-new0").should_not be_nil
  end
end
