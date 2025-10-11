require "./spec_helper"

describe "Dynamic Client Registration" do
  describe Authly::DynamicClient do
    it "creates a dynamic client from valid registration request" do
      params = {
        "redirect_uris"  => JSON::Any.new(["https://example.com/callback"].map { |uri| JSON::Any.new(uri) }),
        "client_name"    => JSON::Any.new("Test Application"),
        "grant_types"    => JSON::Any.new(["authorization_code", "refresh_token"].map { |grant_type| JSON::Any.new(grant_type) }),
        "response_types" => JSON::Any.new(["code"].map { |response_type| JSON::Any.new(response_type) }),
      }

      client = Authly::DynamicClient.from_registration_request(params)

      client.client_id.should start_with("client_")
      client.client_secret.should_not be_nil
      client.redirect_uris.should eq(["https://example.com/callback"])
      client.client_name.should eq("Test Application")
      client.grant_types.should eq(["authorization_code", "refresh_token"])
      client.response_types.should eq(["code"])
    end

    it "generates client without secret for public clients" do
      params = {
        "redirect_uris"              => JSON::Any.new(["https://example.com/callback"].map { |uri| JSON::Any.new(uri) }),
        "token_endpoint_auth_method" => JSON::Any.new("none"),
      }

      client = Authly::DynamicClient.from_registration_request(params)

      client.client_secret.should be_nil
      client.token_endpoint_auth_method.should eq("none")
    end

    it "validates required redirect_uris" do
      params = {} of String => JSON::Any

      expect_raises(Authly::Error) do
        Authly::DynamicClient.from_registration_request(params)
      end
    end

    it "validates URIs are well-formed" do
      client = Authly::DynamicClient.new(
        client_id: "test123",
        client_secret: "secret",
        redirect_uris: ["https://example.com/callback"],
        client_uri: "not_a_uri"
      )

      client.valid?.should be_false
    end

    it "accepts valid client metadata" do
      client = Authly::DynamicClient.new(
        client_id: "test123",
        client_secret: "secret",
        redirect_uris: ["https://example.com/callback"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "My App",
        client_uri: "https://example.com",
        scope: "read write"
      )

      client.valid?.should be_true
    end

    it "rejects unsupported grant types" do
      client = Authly::DynamicClient.new(
        client_id: "test123",
        client_secret: "secret",
        redirect_uris: ["https://example.com/callback"],
        grant_types: ["unsupported_grant"],
        response_types: ["code"]
      )

      client.valid?.should be_false
    end

    it "serializes to JSON correctly" do
      client = Authly::DynamicClient.new(
        client_id: "test123",
        client_secret: "secret",
        redirect_uris: ["https://example.com/callback"],
        client_name: "My App"
      )

      json = client.to_json
      json.should contain("test123")
      json.should contain("My App")
    end
  end

  describe Authly::InMemoryClientStore do
    it "stores and retrieves clients" do
      store = Authly::InMemoryClientStore.new
      client = Authly::DynamicClient.new(
        client_id: "test123",
        client_secret: "secret",
        redirect_uris: ["https://example.com/callback"]
      )

      store.store(client).should be_true
      retrieved = store.fetch("test123")
      retrieved.should_not be_nil
      if fetched = retrieved
        fetched.client_id.should eq("test123")
      end
    end

    it "updates existing clients" do
      store = Authly::InMemoryClientStore.new
      client = Authly::DynamicClient.new(
        client_id: "test123",
        client_secret: "secret",
        redirect_uris: ["https://example.com/callback"]
      )

      store.store(client)

      updated_client = Authly::DynamicClient.new(
        client_id: "test123",
        client_secret: "new_secret",
        redirect_uris: ["https://example.com/new_callback"]
      )

      store.update(updated_client).should be_true
      retrieved = store.fetch("test123")
      if fetched = retrieved
        fetched.redirect_uris.should eq(["https://example.com/new_callback"])
      end
    end

    it "deletes clients" do
      store = Authly::InMemoryClientStore.new
      client = Authly::DynamicClient.new(
        client_id: "test123",
        client_secret: "secret",
        redirect_uris: ["https://example.com/callback"]
      )

      store.store(client)
      store.delete("test123").should be_true
      store.fetch("test123").should be_nil
    end

    it "returns false when updating non-existent client" do
      store = Authly::InMemoryClientStore.new
      client = Authly::DynamicClient.new(
        client_id: "nonexistent",
        client_secret: "secret",
        redirect_uris: ["https://example.com/callback"]
      )

      store.update(client).should be_false
    end
  end
end
