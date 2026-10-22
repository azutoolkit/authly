# Spec file for testing the Grant class and its compliance with OAuth2 specifications
require "./spec_helper"

module Authly
  describe Grant do
    client_id = "1"
    client_secret = "secret"
    username = "username"
    password = "password"
    redirect_uri = "https://www.example.com/callback"
    refresh_token = Authly.jwt_encode({
      "jti"  => Random::Secure.hex(32),
      "sub"  => client_id,
      "name" => "refresh token",
      "iat"  => Time.utc.to_unix,
      "iss"  => Authly.config.issuer,
      "exp"  => Authly.config.refresh_ttl.from_now.to_unix,
    })
    # A code is single use, so every example needs its own.
    authorization_code = -> { Authly::Code.new(client_id, "read", redirect_uri, "", "", username).to_s }

    it "creates an access token with valid client credentials grant" do
      grant = Grant.new("client_credentials", client_id: client_id, client_secret: client_secret)
      token = grant.token

      token.client_id.should eq client_id
      token.scope.should eq ""
    end

    it "creates an access token with valid password grant" do
      grant = Grant.new("password",
        client_id: client_id,
        client_secret: client_secret,
        username: username,
        password: password)

      token = grant.token

      token.client_id.should eq client_id
      token.scope.should eq ""
    end

    it "creates an access token with valid authorization code grant" do
      grant = Grant.new("authorization_code",
        client_id: client_id,
        client_secret: client_secret,
        redirect_uri: redirect_uri,
        code: authorization_code.call)

      token = grant.token

      token.client_id.should eq client_id
      token.scope.should eq "read"
    end

    describe "the sub claim" do
      owner_id = ->(name : String) { Authly.owners.id_token(name)["sub"].to_s }

      it "is the client for a client credentials token" do
        token = Grant.new("client_credentials", client_id: client_id, client_secret: client_secret).token

        token.sub.should eq client_id
      end

      it "is the owner's id for a password grant token, matching the ID token" do
        token = Grant.new("password", client_id: client_id, client_secret: client_secret, username: username, password: password).token

        token.sub.should eq owner_id.call(username)
      end

      it "is the owner's id for the user the authorization code was issued to" do
        code = Authly::Code.new(client_id, "read", redirect_uri, "", "", username).to_s
        token = Grant.new("authorization_code", client_id: client_id, client_secret: client_secret, redirect_uri: redirect_uri, code: code).token

        token.sub.should eq owner_id.call(username)
        Authly.jwt_decode(token.access_token).first["sub"].as_s.should eq owner_id.call(username)
      end

      it "falls back to the user name for a user the owner store does not know" do
        code = Authly::Code.new(client_id, "read", redirect_uri, "", "", "user-42").to_s
        token = Grant.new("authorization_code", client_id: client_id, client_secret: client_secret, redirect_uri: redirect_uri, code: code).token

        token.sub.should eq "user-42"
      end

      it "stays with the owner when the token is refreshed" do
        first = Grant.new("password", client_id: client_id, client_secret: client_secret, username: username, password: password).token
        refreshed = Grant.new("refresh_token", client_id: client_id, client_secret: client_secret, refresh_token: first.refresh_token).token

        refreshed.sub.should eq first.sub
      end

      it "is not shared between anonymous tokens, so unrelated subjects never collide" do
        code = Authly::Code.new(client_id, "read", redirect_uri).to_s
        first = Grant.new("authorization_code", client_id: client_id, client_secret: client_secret, redirect_uri: redirect_uri, code: code).token
        second = Grant.new("authorization_code", client_id: client_id, client_secret: client_secret, redirect_uri: redirect_uri, code: Authly::Code.new(client_id, "read", redirect_uri).to_s).token

        first.sub.should_not eq second.sub
        first.sub.should_not eq client_id
      end
    end

    it "creates an access token with valid refresh token grant" do
      grant = Grant.new("refresh_token",
        client_id: client_id,
        client_secret: client_secret,
        refresh_token: refresh_token,
        code: authorization_code.call)

      token = grant.token

      token.client_id.should eq client_id
      token.scope.should eq "read"
    end

    it "raises error for unsupported grant type" do
      expect_raises(Error) { Grant.new("unsupported_grant_type", client_id: client_id, client_secret: client_secret) }
    end

    it "validates scope for access token" do
      grant = Grant.new("authorization_code",
        client_id: client_id,
        client_secret: client_secret,
        redirect_uri: redirect_uri,
        code: authorization_code.call)

      token = grant.token

      token.scope.should eq "read"
    end

    it "raises error for invalid scope" do
      scope = "pluto"
      invalid_scope = "mars"
      Authly.clients << Authly::Client.new("new_client", "secret", "https://www.example.com/callback", "2", scope)
      invalid_code = Authly::Code.new("2", invalid_scope, redirect_uri, "", "", username).to_s

      grant = Grant.new("authorization_code",
        client_id: "2",
        client_secret: client_secret,
        redirect_uri: redirect_uri,
        code: invalid_code)

      expect_raises(Error) { grant.token }
    end
  end
end
