require "./spec_helper"

module Authly
  describe InMemoryPARStore do
    it "stores and retrieves authorization parameters" do
      store = InMemoryPARStore.new
      request_uri = "urn:ietf:params:oauth:request_uri:test123"
      params = {
        "response_type"         => "code",
        "client_id"             => "test_client",
        "redirect_uri"          => "https://example.com/callback",
        "scope"                 => "openid profile",
        "code_challenge"        => "challenge123",
        "code_challenge_method" => "S256",
        "state"                 => "state123",
      }
      client_id = "test_client"

      store.store(request_uri, params, client_id)

      par_data = store.fetch(request_uri)
      par_data.should_not be_nil
      par_data.not_nil!.params.should eq(params)
      par_data.not_nil!.client_id.should eq(client_id)
    end

    it "returns nil for non-existent request_uri" do
      store = InMemoryPARStore.new
      par_data = store.fetch("urn:ietf:params:oauth:request_uri:nonexistent")
      par_data.should be_nil
    end

    it "validates request_uri exists" do
      store = InMemoryPARStore.new
      request_uri = "urn:ietf:params:oauth:request_uri:test456"
      params = {"client_id" => "test"}
      client_id = "test"

      store.store(request_uri, params, client_id)
      store.valid?(request_uri).should be_true

      store.valid?("urn:ietf:params:oauth:request_uri:invalid").should be_false
    end

    it "consumes request_uri after use (single-use)" do
      store = InMemoryPARStore.new
      request_uri = "urn:ietf:params:oauth:request_uri:test789"
      params = {"client_id" => "test"}
      client_id = "test"

      store.store(request_uri, params, client_id)
      store.valid?(request_uri).should be_true

      # First fetch should work
      par_data = store.fetch(request_uri)
      par_data.should_not be_nil

      # Consume the request_uri
      store.consume(request_uri)

      # Second fetch should fail (single-use)
      store.valid?(request_uri).should be_false
      store.fetch(request_uri).should be_nil
    end

    it "expires request_uri after TTL" do
      store = InMemoryPARStore.new
      request_uri = "urn:ietf:params:oauth:request_uri:expiring"
      params = {"client_id" => "test"}
      client_id = "test"

      # Store with very short TTL
      store.store(request_uri, params, client_id, 0.seconds)

      # Should be expired immediately
      store.valid?(request_uri).should be_false
      store.fetch(request_uri).should be_nil
    end

    it "cleans up expired request URIs" do
      store = InMemoryPARStore.new
      expired_uri = "urn:ietf:params:oauth:request_uri:expired"
      valid_uri = "urn:ietf:params:oauth:request_uri:valid"
      params = {"client_id" => "test"}
      client_id = "test"

      # Store one expired, one valid
      store.store(expired_uri, params, client_id, 0.seconds)
      store.store(valid_uri, params, client_id, 90.seconds)

      store.cleanup_expired

      store.valid?(expired_uri).should be_false
      store.valid?(valid_uri).should be_true
    end

    it "stores client_id with PAR data" do
      store = InMemoryPARStore.new
      request_uri = "urn:ietf:params:oauth:request_uri:client_test"
      params = {"response_type" => "code"}
      client_id = "specific_client_123"

      store.store(request_uri, params, client_id)

      par_data = store.fetch(request_uri)
      par_data.should_not be_nil
      par_data.not_nil!.client_id.should eq(client_id)
    end

    it "prevents replay attacks with single-use consumption" do
      store = InMemoryPARStore.new
      request_uri = "urn:ietf:params:oauth:request_uri:replay_test"
      params = {"client_id" => "test"}
      client_id = "test"

      store.store(request_uri, params, client_id)

      # First use should be valid
      store.valid?(request_uri).should be_true
      store.consume(request_uri)

      # Second use should fail (replay attack prevention)
      store.valid?(request_uri).should be_false
      store.fetch(request_uri).should be_nil
    end

    it "uses default TTL of 90 seconds" do
      store = InMemoryPARStore.new(90.seconds)
      request_uri = "urn:ietf:params:oauth:request_uri:ttl_test"
      params = {"client_id" => "test"}
      client_id = "test"

      store.store(request_uri, params, client_id)

      par_data = store.fetch(request_uri)
      par_data.should_not be_nil

      # Check that expiration is set (approximately 90 seconds from now)
      expires_at = par_data.not_nil!.expires_at
      time_diff = expires_at - Time.utc
      time_diff.should be_close(90.seconds, 1.second)
    end
  end
end
