require "./spec_helper"

module Authly
  describe "Token Strategy" do
    client_id = "1"
    scope = "read"

    describe "JWT Token Strategy" do
      it "generates JWT access tokens" do
        # Ensure JWT strategy is active
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)

        # JWT tokens should be decodable
        decoded, _header = Authly.jwt_decode(token.access_token)
        decoded["cid"].should eq client_id
        decoded["scope"].should eq scope

        Authly.config.token_strategy = original_strategy
      end

      it "generates JWT refresh tokens" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)

        # JWT refresh tokens should be decodable
        decoded, _header = Authly.jwt_decode(token.refresh_token)
        decoded["sub"].should eq client_id

        Authly.config.token_strategy = original_strategy
      end

      it "validates JWT tokens correctly" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)
        Authly.valid?(token.access_token).should be_true

        Authly.config.token_strategy = original_strategy
      end

      it "revokes JWT tokens" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)
        Authly.revoke(token.access_token)
        Authly.revoked?(token.access_token).should be_true

        Authly.config.token_strategy = original_strategy
      end

      it "introspects JWT tokens" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt

        token = AccessToken.new(client_id, scope)
        result = Authly.introspect(token.access_token)

        result["active"].should be_true
        result["cid"].should eq client_id
        result["scope"].should eq scope

        Authly.config.token_strategy = original_strategy
      end
    end

    describe "Opaque Token Strategy" do
      it "generates opaque access tokens" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :opaque

        token = AccessToken.new(client_id, scope)

        # Opaque tokens should not be JWTs (should be random hex)
        token.access_token.should match(/^[a-f0-9]{64}$/)

        # Should not be decodable as JWT
        expect_raises(JWT::DecodeError) do
          Authly.jwt_decode(token.access_token)
        end

        Authly.config.token_strategy = original_strategy
      end

      it "stores opaque token metadata" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :opaque

        token = AccessToken.new(client_id, scope)

        # Metadata should be stored in token_store using access_token as key
        metadata = Authly.config.token_store.fetch(token.access_token)
        metadata.should_not be_nil
        metadata["cid"].to_s.should eq client_id
        metadata["scope"].to_s.should eq scope

        Authly.config.token_strategy = original_strategy
      end

      it "validates opaque tokens correctly" do
        original_strategy = Authly.config.token_strategy
        original_store = Authly.config.token_store
        Authly.config.token_strategy = :opaque
        Authly.config.token_store = InMemoryStore.new

        token = AccessToken.new(client_id, scope)

        # Token should be valid
        manager = TokenManager.new(token_manager: OpaqueToken.new)
        manager.valid?(token.access_token).should be_true

        Authly.config.token_strategy = original_strategy
        Authly.config.token_store = original_store
      end

      it "revokes opaque tokens" do
        original_strategy = Authly.config.token_strategy
        original_store = Authly.config.token_store
        Authly.config.token_strategy = :opaque
        Authly.config.token_store = InMemoryStore.new

        token = AccessToken.new(client_id, scope)

        manager = TokenManager.new(token_manager: OpaqueToken.new)
        manager.revoke(token.access_token)
        manager.revoked?(token.access_token).should be_true

        Authly.config.token_strategy = original_strategy
        Authly.config.token_store = original_store
      end

      it "introspects opaque tokens" do
        original_strategy = Authly.config.token_strategy
        original_store = Authly.config.token_store
        Authly.config.token_strategy = :opaque
        Authly.config.token_store = InMemoryStore.new

        token = AccessToken.new(client_id, scope)

        manager = TokenManager.new(token_manager: OpaqueToken.new)
        result = manager.introspect(token.access_token)

        result["active"].should be_true
        result["cid"].should eq client_id
        result["scope"].should eq scope

        Authly.config.token_strategy = original_strategy
        Authly.config.token_store = original_store
      end
    end
  end

  describe "refresh tokens are not access tokens" do
    it "are not valid for a JWT strategy, and introspect as inactive" do
      issued = AccessToken.new("1", "read", subject: "john")
      strategy = JWTToken.new

      strategy.valid?(issued.access_token).should be_true
      strategy.valid?(issued.refresh_token).should be_false
      strategy.introspect(issued.refresh_token).should eq({"active" => false})
      strategy.introspect(issued.access_token)["active"].should be_true
    end

    it "are not valid for an opaque strategy, and introspect as inactive" do
      original = Authly.config.token_strategy
      Authly.config.token_strategy = :opaque
      begin
        issued = AccessToken.new("1", "read", subject: "john")
        strategy = OpaqueToken.new

        strategy.valid?(issued.access_token).should be_true
        strategy.valid?(issued.refresh_token).should be_false
        strategy.introspect(issued.refresh_token).should eq({"active" => false})
        strategy.introspect(issued.access_token)["active"].should be_true
      ensure
        Authly.config.token_strategy = original
      end
    end

    it "are not valid through Authly.valid? and Authly.introspect" do
      issued = AccessToken.new("1", "read", subject: "john")
      Authly.valid?(issued.refresh_token).should be_false
      Authly.introspect(issued.refresh_token).should eq({"active" => false})
    end
  end
end
