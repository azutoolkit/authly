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
    authorization_code = Authly::Code.new(client_id, "read", redirect_uri, "", "", username).to_s

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
        code: authorization_code)

      token = grant.token

      token.client_id.should eq client_id
      token.scope.should eq "read"
    end

    it "creates an access token with valid refresh token grant" do
      grant = Grant.new("refresh_token",
        client_id: client_id,
        client_secret: client_secret,
        refresh_token: refresh_token,
        code: authorization_code)

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
        code: authorization_code)

      token = grant.token

      token.scope.should eq "read"
    end

    it "raises error for invalid scope" do
      scope = "pluto"
      invalid_scope = "mars"
      Authly.clients << Authly::Client.new("new_client", "secret", "https://www.example.com/callback", "2", scope)
      authorization_code = Authly::Code.new("2", invalid_scope, redirect_uri, "", "", username).to_s

      grant = Grant.new("authorization_code",
        client_id: "2",
        client_secret: client_secret,
        redirect_uri: redirect_uri,
        code: authorization_code)

      expect_raises(Error) { grant.token }
    end
  end
end
