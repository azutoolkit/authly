require "./spec_helper"

module Authly
  describe AccessToken do
    describe "with JWT strategy" do
      before_each do
        Authly.config.token_strategy = :jwt
      end

      it "generates access token with valid claims" do
        token = AccessToken.new("client_123", "read write")

        token.access_token.should_not be_nil
        token.token_type.should eq "Bearer"
        token.scope.should eq "read write"
        token.client_id.should eq "client_123"
        token.revoked?.should be_false
      end

      it "generates unique sub and jti for each token" do
        token1 = AccessToken.new("client_1", "read")
        token2 = AccessToken.new("client_1", "read")

        token1.sub.should_not eq token2.sub
        token1.jti.should_not eq token2.jti
      end

      it "generates refresh token along with access token" do
        token = AccessToken.new("client_123", "read")

        token.refresh_token.should_not be_nil
        token.refresh_token.should_not be_empty
      end

      it "sets expiration time based on configured TTL" do
        token = AccessToken.new("client_123", "read")
        expected_expiry = Authly.config.access_ttl.from_now.to_unix

        # Allow 2 second tolerance for test execution time
        token.expires_in.should be_close(expected_expiry, 2)
      end

      it "can decode and verify JWT access token" do
        token = AccessToken.new("client_123", "read write")

        payload, _header = Authly.jwt_decode(token.access_token)
        payload["cid"].should eq "client_123"
        payload["scope"].should eq "read write"
        payload["sub"].should eq token.sub
        payload["jti"].should eq token.jti
      end

      it "includes optional id_token when provided" do
        token = AccessToken.new("client_123", "openid", "id_token_value")

        token.id_token.should eq "id_token_value"
      end

      it "serializes to JSON correctly" do
        token = AccessToken.new("client_123", "read")
        json = JSON.parse(token.to_json)

        json["access_token"].should_not be_nil
        json["token_type"].should eq "Bearer"
        json["scope"].should eq "read"
        json["expires_in"].should_not be_nil
        json["refresh_token"].should_not be_nil
      end

      it "does not include client_id in JSON serialization" do
        token = AccessToken.new("client_123", "read")
        json = JSON.parse(token.to_json)

        json["client_id"]?.should be_nil
      end
    end

    describe "with opaque strategy" do
      before_each do
        Authly.config.token_strategy = :opaque
        Authly.config.token_store = InMemoryStore.new
      end

      after_each do
        Authly.config.token_strategy = :jwt
      end

      it "generates opaque access token (random hex)" do
        token = AccessToken.new("client_123", "read")

        # Opaque tokens should be hex strings
        token.access_token.should match(/^[a-f0-9]+$/)
        token.access_token.size.should eq 64 # 32 bytes = 64 hex chars
      end

      it "stores token metadata in token store" do
        token = AccessToken.new("client_123", "read write")

        payload = Authly.config.token_store.fetch(token.access_token)
        payload["cid"].should eq "client_123"
        payload["scope"].should eq "read write"
        payload["sub"].should eq token.sub
        payload["token_type"].should eq "access_token"
      end

      it "stores refresh token metadata separately" do
        token = AccessToken.new("client_123", "read")

        refresh_payload = Authly.config.token_store.fetch(token.refresh_token)
        refresh_payload["sub"].should eq "client_123"
        refresh_payload["token_type"].should eq "refresh_token"
      end

      it "generates unique random tokens each time" do
        token1 = AccessToken.new("client_1", "read")
        token2 = AccessToken.new("client_1", "read")

        token1.access_token.should_not eq token2.access_token
        token1.refresh_token.should_not eq token2.refresh_token
      end
    end

    describe ".jwt class method" do
      it "creates token and returns JSON string" do
        json_str = AccessToken.jwt("client_123", "read", "id_token")

        json_str.should be_a(String)
        json = JSON.parse(json_str)
        json["access_token"].should_not be_nil
        json["scope"].should eq "read"
      end
    end
  end
end
