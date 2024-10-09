require "./spec_helper"

module Authly
  describe Grant do
    describe "AuthorizationCodeGrant" do
      it "authorizes with valid client, redirect_uri, and verifier" do
        grant = Grant.new("authorization_code",
          client_id: "1",
          client_secret: "secret",
          redirect_uri: "https://www.example.com/callback",
          challenge: "valid_challenge",
          method: "S256")
        grant.authorized?.should be_true
      end

      it "raises error with invalid redirect_uri" do
        grant = Grant.new("authorization_code",
          client_id: "valid_client_id",
          client_secret: "valid_secret",
          redirect_uri: "https://invalid.redirect.uri",
          challenge: "valid_challenge",
          method: "S256",
          verifier: "valid_verifier")

        expect_raises(Authly::Error(400)) { grant.authorized? }
      end
    end

    describe "ClientCredentialsGrant" do
      it "authorizes with valid client credentials" do
        grant = Grant.new("client_credentials",
          client_id: "1",
          client_secret: "secret")

        grant.authorized?.should be_true
      end

      it "raises error with invalid client credentials" do
        grant = Grant.new("client_credentials",
          client_id: "invalid_client_id",
          client_secret: "invalid_secret")
        expect_raises(Authly::Error(401)) { grant.authorized? }
      end
    end

    describe "PasswordGrant" do
      it "authorizes with valid client and user credentials" do
        grant = Grant.new("password",
          client_id: "1",
          client_secret: "secret",
          username: "username",
          password: "password")
        grant.authorized?.should be_true
      end

      it "raises error with invalid user credentials" do
        grant = Grant.new("password",
          client_id: "valid_client_id",
          client_secret: "valid_secret",
          username: "invalid_user",
          password: "invalid_password")
        expect_raises(Authly::Error(401)) { grant.authorized? }
      end
    end

    describe "RefreshTokenGrant" do
      it "authorizes with valid refresh token" do
        client_id, secret, scope = "1", "secret", "read write"
        token = AccessToken.new(client_id, scope).refresh_token

        grant = Grant.new("refresh_token",
          client_id: client_id,
          client_secret: secret,
          refresh_token: token)

        grant.authorized?.should be_true
      end

      it "raises error with invalid refresh token" do
        grant = Grant.new("refresh_token",
          client_id: "valid_client_id",
          client_secret: "valid_secret",
          refresh_token: "invalid_refresh_token")

        expect_raises(Authly::Error(400)) { grant.authorized? }
      end
    end
  end
end
