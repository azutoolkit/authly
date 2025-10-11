require "./spec_helper"

module Authly
  describe JWTTokenGenerator do
    describe "#generate_access_token" do
      it "generates valid JWT access token" do
        generator = JWTTokenGenerator.new
        token = generator.generate_access_token("client_123", "read write", "sub_123", "jti_123")

        token.should_not be_nil
        token.should_not be_empty
      end

      it "includes all required claims in token" do
        generator = JWTTokenGenerator.new
        token = generator.generate_access_token("client_123", "read write", "sub_123", "jti_123")

        payload, _header = Authly.jwt_decode(token)
        payload["cid"].should eq "client_123"
        payload["scope"].should eq "read write"
        payload["sub"].should eq "sub_123"
        payload["jti"].should eq "jti_123"
        payload["iss"].should eq Authly.config.issuer
      end

      it "includes iat and exp claims" do
        generator = JWTTokenGenerator.new
        token = generator.generate_access_token("client_1", "read", "sub_1", "jti_1")

        payload, _header = Authly.jwt_decode(token)
        payload["iat"].should_not be_nil
        payload["exp"].should_not be_nil
        payload["exp"].to_s.to_i64.should be > payload["iat"].to_s.to_i64
      end

      it "generates different tokens for different inputs" do
        generator = JWTTokenGenerator.new
        token1 = generator.generate_access_token("client_1", "read", "sub_1", "jti_1")
        token2 = generator.generate_access_token("client_2", "write", "sub_2", "jti_2")

        token1.should_not eq token2
      end

      it "generates different tokens with different jti even with same client" do
        generator = JWTTokenGenerator.new
        token1 = generator.generate_access_token("client_1", "read", "sub_1", "jti_1")
        token2 = generator.generate_access_token("client_1", "read", "sub_1", "jti_2")

        token1.should_not eq token2
      end
    end

    describe "#generate_refresh_token" do
      it "generates valid JWT refresh token" do
        generator = JWTTokenGenerator.new
        token = generator.generate_refresh_token("client_123", "jti_refresh_123")

        token.should_not be_nil
        token.should_not be_empty
      end

      it "includes required claims in refresh token" do
        generator = JWTTokenGenerator.new
        token = generator.generate_refresh_token("client_123", "jti_refresh_123")

        payload, _header = Authly.jwt_decode(token)
        payload["jti"].should eq "jti_refresh_123"
        payload["sub"].should eq "client_123"
        payload["iss"].should eq Authly.config.issuer
        payload["name"].should eq "refresh token"
      end

      it "sets expiration based on refresh_ttl" do
        generator = JWTTokenGenerator.new
        token = generator.generate_refresh_token("client_1", "jti_1")

        payload, _header = Authly.jwt_decode(token)
        expected_exp = Authly.config.refresh_ttl.from_now.to_unix
        payload["exp"].to_s.to_i64.should be_close(expected_exp, 2)
      end
    end

    describe "#store_token_metadata" do
      it "does not store metadata for JWT tokens" do
        generator = JWTTokenGenerator.new
        store = InMemoryStore.new
        Authly.config.token_store = store

        generator.store_token_metadata("jti_1", "client_1", "read", "sub_1", Time.utc)

        # JWT tokens are self-contained, no metadata stored
        expect_raises(Error) do
          store.fetch("jti_1")
        end
      end
    end
  end

  describe OpaqueTokenGenerator do
    describe "#generate_access_token" do
      it "generates random hex token" do
        generator = OpaqueTokenGenerator.new
        token = generator.generate_access_token("client_1", "read", "sub_1", "jti_1")

        token.should match(/^[a-f0-9]+$/)
        token.size.should eq 64  # 32 bytes = 64 hex chars
      end

      it "generates unique tokens each time" do
        generator = OpaqueTokenGenerator.new
        token1 = generator.generate_access_token("client_1", "read", "sub_1", "jti_1")
        token2 = generator.generate_access_token("client_1", "read", "sub_1", "jti_1")

        token1.should_not eq token2
      end

      it "tokens are not JWT format" do
        generator = OpaqueTokenGenerator.new
        token = generator.generate_access_token("client_1", "read", "sub_1", "jti_1")

        # Opaque tokens should not be decodable as JWT
        expect_raises(JWT::DecodeError) do
          Authly.jwt_decode(token)
        end
      end
    end

    describe "#generate_refresh_token" do
      it "generates random hex token" do
        generator = OpaqueTokenGenerator.new
        token = generator.generate_refresh_token("client_1", "jti_1")

        token.should match(/^[a-f0-9]+$/)
        token.size.should eq 64
      end

      it "generates unique tokens each time" do
        generator = OpaqueTokenGenerator.new
        token1 = generator.generate_refresh_token("client_1", "jti_1")
        token2 = generator.generate_refresh_token("client_1", "jti_1")

        token1.should_not eq token2
      end
    end

    describe "#store_token_metadata" do
      it "stores metadata in token store" do
        generator = OpaqueTokenGenerator.new
        store = InMemoryStore.new
        Authly.config.token_store = store

        expires_at = 1.hour.from_now
        generator.store_token_metadata("jti_1", "client_1", "read write", "sub_1", expires_at)

        payload = store.fetch("jti_1")
        payload["cid"].should eq "client_1"
        payload["scope"].should eq "read write"
        payload["sub"].should eq "sub_1"
        payload["token_type"].should eq "access_token"
      end

      it "stores expiration timestamp" do
        generator = OpaqueTokenGenerator.new
        store = InMemoryStore.new
        Authly.config.token_store = store

        expires_at = 2.hours.from_now
        generator.store_token_metadata("jti_1", "client_1", "read", "sub_1", expires_at)

        payload = store.fetch("jti_1")
        payload["exp"].should eq expires_at.to_unix
      end

      it "stores issued at timestamp" do
        generator = OpaqueTokenGenerator.new
        store = InMemoryStore.new
        Authly.config.token_store = store

        expires_at = 1.hour.from_now
        generator.store_token_metadata("jti_1", "client_1", "read", "sub_1", expires_at)

        payload = store.fetch("jti_1")
        payload["iat"].as(Int64).should be_close(Time.utc.to_unix, 2)
      end
    end
  end

  describe TokenGeneratorFactory do
    describe ".create" do
      it "creates JWT generator when strategy is :jwt" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :jwt
        generator = TokenGeneratorFactory.create

        generator.should be_a(JWTTokenGenerator)

        Authly.config.token_strategy = original_strategy
      end

      it "creates Opaque generator when strategy is :opaque" do
        original_strategy = Authly.config.token_strategy
        Authly.config.token_strategy = :opaque
        generator = TokenGeneratorFactory.create

        generator.should be_a(OpaqueTokenGenerator)

        Authly.config.token_strategy = original_strategy
      end

      it "raises error for unsupported strategy" do
        # Save original
        original_strategy = Authly.config.token_strategy

        # Test with invalid strategy by directly accessing the factory
        expect_raises(Error) do
          Authly.config.token_strategy = :invalid_strategy
          TokenGeneratorFactory.create
        end

        # Restore
        Authly.config.token_strategy = original_strategy
      end
    end
  end
end

