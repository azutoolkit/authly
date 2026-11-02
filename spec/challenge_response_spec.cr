require "./spec_helper"
require "http/server"

module Authly
  private class ChallengeTestContext
    getter io : IO::Memory
    getter context : HTTP::Server::Context

    def initialize(
      method : String,
      path : String,
      form_data : Hash(String, String)? = nil,
      json_body : String? = nil,
      headers : HTTP::Headers? = nil,
    )
      @io = IO::Memory.new
      request = HTTP::Request.new(method, path, headers: headers)

      if form_data
        request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        request.body = HTTP::Params.encode(form_data)
      elsif json_body
        request.headers["Content-Type"] = "application/json"
        request.body = json_body
      end

      response = HTTP::Server::Response.new(@io)
      @context = HTTP::Server::Context.new(request, response)
    end

    def response_body : String
      @context.response.close
      @io.rewind
      response_text = @io.gets_to_end
      if match = response_text.match(/\r\n\r\n(.*)$/m)
        match[1]
      else
        response_text
      end
    end
  end

  describe "Challenge-Response Authentication" do
    before_each do
      Authly.config.challenge_store = InMemoryChallengeStore.new
      Authly.config.challenge_ttl = 60.seconds
      Authly.config.challenge_max_attempts = 1
    end

    describe InMemoryChallengeStore do
      it "stores, fetches, and atomically consumes a challenge once" do
        store = InMemoryChallengeStore.new
        challenge = Challenge.generate(client_id: "1", username: "john")
        store.store(challenge)

        fetched = store.fetch(challenge.challenge_id)
        fetched.should_not be_nil
        fetched.not_nil!.challenge.should eq challenge.challenge
        fetched.not_nil!.client_id.should eq "1"
        fetched.not_nil!.username.should eq "john"
        store.valid?(challenge.challenge_id).should be_true

        consumed = store.consume!(challenge.challenge_id)
        consumed.should_not be_nil
        consumed.not_nil!.consumed?.should be_true

        # Replay attempt must return nil
        store.consume!(challenge.challenge_id).should be_nil
        store.fetch(challenge.challenge_id).should be_nil
        store.valid?(challenge.challenge_id).should be_false
      end

      it "expires challenges after TTL and cleans up expired entries" do
        store = InMemoryChallengeStore.new
        expired = Challenge.generate(client_id: "1", ttl: -1.second)
        active = Challenge.generate(client_id: "1", ttl: 60.seconds)

        store.store(expired)
        store.store(active)

        store.fetch(expired.challenge_id).should be_nil
        store.consume!(expired.challenge_id).should be_nil
        store.fetch(active.challenge_id).should_not be_nil

        store.store(Challenge.generate(client_id: "1", ttl: -5.seconds))
        store.cleanup_expired
        store.size.should eq 1
      end

      it "automatically sweeps expired challenges when threshold is reached" do
        store = InMemoryChallengeStore.new
        300.times do |i|
          store.store(Challenge.new("exp-#{i}", "nonce-#{i}", "1", 1.minute.ago))
        end
        64.times do |i|
          store.store(Challenge.new("act-#{i}", "nonce-#{i}", "1", 1.minute.from_now))
        end

        store.size.should eq 64
      end
    end

    describe "POST /oauth/challenge" do
      it "issues a cryptographically random challenge for a valid client" do
        ctx = ChallengeTestContext.new("POST", "/oauth/challenge", form_data: {
          "client_id" => "1",
          "username"  => "john",
        })
        OAUTH_HANDLER.call(ctx.context)

        ctx.context.response.status_code.should eq 200
        ctx.context.response.headers["Cache-Control"]?.should eq "no-store"

        body = JSON.parse(ctx.response_body)
        challenge_id = body["challenge_id"].as_s
        challenge = body["challenge"].as_s
        expires_in = body["expires_in"].as_i

        challenge_id.size.should eq 32
        challenge.size.should eq 64
        expires_in.should eq 60

        stored = Authly.config.challenge_store.fetch(challenge_id)
        stored.should_not be_nil
        stored.not_nil!.challenge.should eq challenge
        stored.not_nil!.client_id.should eq "1"
        stored.not_nil!.username.should eq "john"
      end

      it "accepts JSON request body and owner_id / key_id identifiers" do
        ctx = ChallengeTestContext.new(
          "POST",
          "/oauth/challenge",
          json_body: {client_id: "1", owner_id: "owner-42", key_id: "key-1"}.to_json
        )
        OAUTH_HANDLER.call(ctx.context)

        ctx.context.response.status_code.should eq 200
        body = JSON.parse(ctx.response_body)
        stored = Authly.config.challenge_store.fetch(body["challenge_id"].as_s).not_nil!
        stored.owner_id.should eq "owner-42"
        stored.key_id.should eq "key-1"
      end

      it "returns 400 invalid_request when client_id is missing" do
        ctx = ChallengeTestContext.new("POST", "/oauth/challenge", form_data: {} of String => String)
        OAUTH_HANDLER.call(ctx.context)

        ctx.context.response.status_code.should eq 400
        JSON.parse(ctx.response_body)["error"].as_s.should eq "invalid_request"
      end

      it "returns 401 invalid_client when client_id is unknown or secret is invalid" do
        ctx = ChallengeTestContext.new("POST", "/oauth/challenge", form_data: {
          "client_id" => "unknown-client",
        })
        OAUTH_HANDLER.call(ctx.context)

        ctx.context.response.status_code.should eq 401
        JSON.parse(ctx.response_body)["error"].as_s.should eq "invalid_client"

        ctx_bad_secret = ChallengeTestContext.new("POST", "/oauth/challenge", form_data: {
          "client_id"     => "1",
          "client_secret" => "wrong-secret",
        })
        OAUTH_HANDLER.call(ctx_bad_secret.context)

        ctx_bad_secret.context.response.status_code.should eq 401
        JSON.parse(ctx_bad_secret.response_body)["error"].as_s.should eq "invalid_client"
      end
    end

    describe "POST /oauth/token (Challenge Verification & Token Exchange)" do
      it "exchanges a valid HMAC-SHA256 client challenge response for a JWT access token" do
        challenge_data = ChallengeResponse.create_challenge(client_id: "1")
        signature = OpenSSL::HMAC.hexdigest(:sha256, "secret", challenge_data.challenge)

        ctx = ChallengeTestContext.new("POST", "/oauth/token", form_data: {
          "grant_type"   => "challenge_response",
          "client_id"    => "1",
          "challenge_id" => challenge_data.challenge_id,
          "response"     => signature,
          "scope"        => "read write",
        })
        OAUTH_HANDLER.call(ctx.context)

        ctx.context.response.status_code.should eq 200
        body = JSON.parse(ctx.response_body)
        body["access_token"].as_s.should_not be_empty
        body["token_type"].as_s.should eq "Bearer"
        body["scope"].as_s.should eq "read write"
        body["refresh_token"].as_s.should_not be_empty

        claims, _ = Authly.jwt_decode(body["access_token"].as_s)
        claims["cid"].as_s.should eq "1"
        claims["sub"].as_s.should eq "1"
        claims["scope"].as_s.should eq "read write"
      end

      it "supports urn:ietf:params:oauth:grant-type:challenge and owner HMAC verification" do
        challenge_data = ChallengeResponse.create_challenge(client_id: "1", username: "john")
        signature_b64 = Base64.urlsafe_encode(
          OpenSSL::HMAC.digest(:sha256, "secret", challenge_data.challenge),
          padding: false
        )

        ctx = ChallengeTestContext.new("POST", "/oauth/token", form_data: {
          "grant_type"   => "urn:ietf:params:oauth:grant-type:challenge",
          "client_id"    => "1",
          "challenge_id" => challenge_data.challenge_id,
          "response"     => signature_b64,
          "scope"        => "read",
        })
        OAUTH_HANDLER.call(ctx.context)

        ctx.context.response.status_code.should eq 200
        body = JSON.parse(ctx.response_body)
        claims, _ = Authly.jwt_decode(body["access_token"].as_s)
        claims["sub"].as_s.should eq Authly.owners.id_token("john")["sub"].to_s
      end

      it "supports Ed25519 asymmetric signature verification" do
        signing_key = Ed25519::SigningKey.new
        public_key_hex = signing_key.verify_key.key_bytes.hexstring

        Authly.owners << Owner.new(
          username: "ed_user",
          password: "",
          public_key: public_key_hex,
          key_id: "ed-key-1",
          id: "sub-ed-user",
        )

        challenge_data = ChallengeResponse.create_challenge(client_id: "1", key_id: "ed-key-1")
        sig_bytes = signing_key.sign(challenge_data.challenge.to_slice)
        response_hex = sig_bytes.hexstring

        token = Authly.access_token(
          "challenge_response",
          client_id: "1",
          challenge_id: challenge_data.challenge_id,
          response: response_hex,
          scope: "read",
        )

        token.sub.should eq "sub-ed-user"
        token.scope.should eq "read"
      end

      it "supports RSA (OpenSSL::PKey::RSA) asymmetric signature verification" do
        rsa_key = OpenSSL::PKey::RSA.new(2048)
        public_pem = rsa_key.public_key.to_pem

        Authly.clients << Client.new(
          name: "rsa_client",
          secret: "rsa_secret",
          redirect_uri: "https://example.com/cb",
          id: "rsa_client",
          scopes: "read write",
          public_key: public_pem,
        )

        challenge_data = ChallengeResponse.create_challenge(client_id: "rsa_client")
        sig = rsa_key.sign(OpenSSL::Digest.new("sha256"), challenge_data.challenge)
        response_b64 = Base64.strict_encode(sig)

        token = Authly.access_token(
          "challenge_response",
          client_id: "rsa_client",
          challenge_id: challenge_data.challenge_id,
          response: response_b64,
          scope: "read",
        )

        token.client_id.should eq "rsa_client"
        token.sub.should eq "rsa_client"
      end

      it "supports ECDSA (OpenSSL::PKey::EC P-256) DER and raw P1363 signature verification" do
        ec_key = OpenSSL::PKey::EC.generate("P-256")
        public_pem = ec_key.public_key.to_pem

        Authly.owners << Owner.new(
          username: "ec_user",
          password: "",
          public_key: public_pem,
          id: "sub-ec-user",
        )

        # 1. ASN.1 DER signature
        c1 = ChallengeResponse.create_challenge(client_id: "1", username: "ec_user")
        digest1 = OpenSSL::Digest.new("sha256").update(c1.challenge).final
        der_sig = ec_key.ec_sign(digest1)

        t1 = Authly.access_token(
          "challenge_response",
          client_id: "1",
          challenge_id: c1.challenge_id,
          response: Base64.strict_encode(der_sig),
          scope: "read",
        )
        t1.sub.should eq "sub-ec-user"

        # 2. Raw (r || s) IEEE P1363 signature
        c2 = ChallengeResponse.create_challenge(client_id: "1", username: "ec_user")
        digest2 = OpenSSL::Digest.new("sha256").update(c2.challenge).final
        raw_sig = JWT.asn1_to_raw(ec_key.ec_sign(digest2), ec_key)

        t2 = Authly.access_token(
          "challenge_response",
          client_id: "1",
          challenge_id: c2.challenge_id,
          response: Base64.urlsafe_encode(raw_sig, padding: false),
          scope: "read",
        )
        t2.sub.should eq "sub-ec-user"
      end

      it "issues opaque tokens when TokenStrategy is :opaque" do
        Authly.config.token_strategy = :opaque
        Authly.config.token_store = InMemoryStore.new

        challenge_data = ChallengeResponse.create_challenge(client_id: "1")
        signature = OpenSSL::HMAC.hexdigest(:sha256, "secret", challenge_data.challenge)

        token = Authly.access_token(
          "challenge_response",
          client_id: "1",
          challenge_id: challenge_data.challenge_id,
          response: signature,
          scope: "read",
        )

        token.access_token.size.should eq 64
        Authly.valid?(token.access_token).should be_true
        introspected = Authly.introspect(token.access_token)
        introspected["active"].should be_true
        introspected["cid"].should eq "1"
      end

      it "rejects expired challenges with expired_challenge error" do
        challenge_data = ChallengeResponse.create_challenge(client_id: "1", ttl: -1.second)
        signature = OpenSSL::HMAC.hexdigest(:sha256, "secret", challenge_data.challenge)

        expect_raises(Error(400), ERROR_MSG[:expired_challenge]) do
          Authly.access_token(
            "challenge_response",
            client_id: "1",
            challenge_id: challenge_data.challenge_id,
            response: signature,
            scope: "read",
          )
        end

        # Verify HTTP endpoint also returns expired_challenge
        expired2 = ChallengeResponse.create_challenge(client_id: "1", ttl: -1.second)
        sig2 = OpenSSL::HMAC.hexdigest(:sha256, "secret", expired2.challenge)
        ctx = ChallengeTestContext.new("POST", "/oauth/token", form_data: {
          "grant_type"   => "challenge_response",
          "client_id"    => "1",
          "challenge_id" => expired2.challenge_id,
          "response"     => sig2,
        })
        OAUTH_HANDLER.call(ctx.context)

        ctx.context.response.status_code.should eq 400
        JSON.parse(ctx.response_body)["error"].as_s.should eq "expired_challenge"
      end

      it "prevents replay attacks by rejecting a second exchange of the same challenge" do
        challenge_data = ChallengeResponse.create_challenge(client_id: "1")
        signature = OpenSSL::HMAC.hexdigest(:sha256, "secret", challenge_data.challenge)

        first = Authly.access_token(
          "challenge_response",
          client_id: "1",
          challenge_id: challenge_data.challenge_id,
          response: signature,
          scope: "read",
        )
        first.access_token.should_not be_empty

        # Second attempt (replay) must fail with invalid_grant
        expect_raises(Error(400), ERROR_MSG[:invalid_grant]) do
          Authly.access_token(
            "challenge_response",
            client_id: "1",
            challenge_id: challenge_data.challenge_id,
            response: signature,
            scope: "read",
          )
        end
      end

      it "immediately invalidates the challenge on an invalid signature to prevent brute-force attacks" do
        challenge_data = ChallengeResponse.create_challenge(client_id: "1")
        valid_signature = OpenSSL::HMAC.hexdigest(:sha256, "secret", challenge_data.challenge)

        # First attempt with forged signature fails
        expect_raises(Error(400), ERROR_MSG[:invalid_grant]) do
          Authly.access_token(
            "challenge_response",
            client_id: "1",
            challenge_id: challenge_data.challenge_id,
            response: "00" * 32,
            scope: "read",
          )
        end

        # Challenge must now be invalidated; presenting the valid signature afterward must also fail
        expect_raises(Error(400), ERROR_MSG[:invalid_grant]) do
          Authly.access_token(
            "challenge_response",
            client_id: "1",
            challenge_id: challenge_data.challenge_id,
            response: valid_signature,
            scope: "read",
          )
        end
      end

      it "rejects mismatched client_id and invalidates the challenge" do
        challenge_data = ChallengeResponse.create_challenge(client_id: "1")
        valid_signature = OpenSSL::HMAC.hexdigest(:sha256, "secret", challenge_data.challenge)

        # Attempt to redeem using "test_client" instead of "1"
        expect_raises(Error(400), ERROR_MSG[:invalid_grant]) do
          Authly.access_token(
            "challenge_response",
            client_id: "test_client",
            challenge_id: challenge_data.challenge_id,
            response: valid_signature,
            scope: "read",
          )
        end

        # Subsequent attempt by the original client must also fail because the challenge was burned
        expect_raises(Error(400), ERROR_MSG[:invalid_grant]) do
          Authly.access_token(
            "challenge_response",
            client_id: "1",
            challenge_id: challenge_data.challenge_id,
            response: valid_signature,
            scope: "read",
          )
        end
      end
    end
  end
end
