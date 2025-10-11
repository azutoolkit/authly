require "./spec_helper"

module Authly
  describe InMemoryStore do
    describe "#store" do
      it "stores token payload by token_id" do
        store = InMemoryStore.new
        payload = {"cid" => "client_1", "scope" => "read"} of String => (String | Int64 | Bool | Float64)

        store.store("token_123", payload)
        fetched = store.fetch("token_123")
        fetched["cid"].should eq "client_1"
        fetched["scope"].should eq "read"
      end

      it "stores multiple tokens independently" do
        store = InMemoryStore.new
        payload1 = {"cid" => "client_1"} of String => (String | Int64 | Bool | Float64)
        payload2 = {"cid" => "client_2"} of String => (String | Int64 | Bool | Float64)

        store.store("token_1", payload1)
        store.store("token_2", payload2)

        store.fetch("token_1")["cid"].should eq "client_1"
        store.fetch("token_2")["cid"].should eq "client_2"
      end

      it "overwrites existing token with same token_id" do
        store = InMemoryStore.new
        payload1 = {"cid" => "client_1"} of String => (String | Int64 | Bool | Float64)
        payload2 = {"cid" => "client_2"} of String => (String | Int64 | Bool | Float64)

        store.store("token_1", payload1)
        store.store("token_1", payload2)

        store.fetch("token_1")["cid"].should eq "client_2"
      end

      it "stores different data types in payload" do
        store = InMemoryStore.new
        payload = {
          "string_val" => "test",
          "int_val"    => 123_i64,
          "bool_val"   => true,
          "float_val"  => 3.14,
        } of String => (String | Int64 | Bool | Float64)

        store.store("token_1", payload)
        fetched = store.fetch("token_1")

        fetched["string_val"].should eq "test"
        fetched["int_val"].should eq 123_i64
        fetched["bool_val"].should eq true
        fetched["float_val"].should eq 3.14
      end
    end

    describe "#fetch" do
      it "fetches stored token payload" do
        store = InMemoryStore.new
        payload = {"cid" => "client_1", "scope" => "read"} of String => (String | Int64 | Bool | Float64)
        store.store("token_1", payload)

        result = store.fetch("token_1")
        result.should eq payload
      end

      it "raises Error for non-existent token" do
        store = InMemoryStore.new

        expect_raises(Error, "The token is invalid or expired") do
          store.fetch("non_existent_token")
        end
      end
    end

    describe "#revoke" do
      it "marks token as revoked" do
        store = InMemoryStore.new

        store.revoke("token_1")
        store.revoked?("token_1").should be_true
      end

      it "allows revoking multiple tokens" do
        store = InMemoryStore.new

        store.revoke("token_1")
        store.revoke("token_2")

        store.revoked?("token_1").should be_true
        store.revoked?("token_2").should be_true
      end

      it "revocation is idempotent" do
        store = InMemoryStore.new

        store.revoke("token_1")
        store.revoke("token_1") # Revoke again

        store.revoked?("token_1").should be_true
      end

      it "revokes token without requiring it to be stored first" do
        store = InMemoryStore.new

        store.revoke("token_never_stored")
        store.revoked?("token_never_stored").should be_true
      end
    end

    describe "#revoked?" do
      it "returns true for revoked token" do
        store = InMemoryStore.new
        store.revoke("token_1")

        store.revoked?("token_1").should be_true
      end

      it "returns false for non-revoked token" do
        store = InMemoryStore.new
        payload = {"cid" => "client_1"} of String => (String | Int64 | Bool | Float64)
        store.store("token_1", payload)

        store.revoked?("token_1").should be_false
      end

      it "returns false for unknown token" do
        store = InMemoryStore.new

        store.revoked?("unknown_token").should be_false
      end
    end

    describe "#valid?" do
      it "returns true for non-revoked token" do
        store = InMemoryStore.new

        store.valid?("token_1").should be_true
      end

      it "returns false for revoked token" do
        store = InMemoryStore.new
        store.revoke("token_1")

        store.valid?("token_1").should be_false
      end
    end

    describe "#each (Enumerable)" do
      it "iterates over revoked tokens" do
        store = InMemoryStore.new
        store.revoke("token_1")
        store.revoke("token_2")
        store.revoke("token_3")

        revoked_tokens = [] of String
        store.each { |token_id| revoked_tokens << token_id }

        revoked_tokens.size.should eq 3
        revoked_tokens.should contain("token_1")
        revoked_tokens.should contain("token_2")
        revoked_tokens.should contain("token_3")
      end

      it "yields nothing when no tokens are revoked" do
        store = InMemoryStore.new

        count = 0
        store.each { count += 1 }
        count.should eq 0
      end
    end

    describe "integration scenarios" do
      it "handles store, revoke, and fetch operations together" do
        store = InMemoryStore.new
        payload = {"cid" => "client_1", "scope" => "read"} of String => (String | Int64 | Bool | Float64)

        store.store("token_1", payload)
        store.fetch("token_1")["cid"].should eq "client_1"

        store.revoke("token_1")
        store.revoked?("token_1").should be_true

        # Can still fetch revoked token payload
        store.fetch("token_1")["cid"].should eq "client_1"
      end

      it "maintains separate storage for payloads and revocations" do
        store = InMemoryStore.new
        payload1 = {"cid" => "client_1"} of String => (String | Int64 | Bool | Float64)
        payload2 = {"cid" => "client_2"} of String => (String | Int64 | Bool | Float64)

        store.store("token_1", payload1)
        store.store("token_2", payload2)
        store.revoke("token_1")

        store.revoked?("token_1").should be_true
        store.revoked?("token_2").should be_false
        store.fetch("token_2")["cid"].should eq "client_2"
      end
    end
  end
end
