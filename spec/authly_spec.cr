require "./spec_helper"

describe Authly do
  client_id = "1"
  client_secret = "secret"
  state = "state"
  scope = "scope"
  redirect_uri = "https://www.example.com/callback"
  code_challenge = "code_challenge"
  code_challenge_method = "S256"

  describe ".access_token" do
    describe "openid" do
      it "gets id token" do
        openid_scope = "openid read"
        code = Authly::Code.new(
          client_id, openid_scope, redirect_uri, user_id: "username").to_s

        token = Authly.access_token(
          grant_type: "authorization_code",
          client_id: client_id,
          client_secret: client_secret,
          redirect_uri: redirect_uri,
          code: code,
          state: state,
          scope: openid_scope)
        it_token = Authly.jwt_decode(token.id_token.not_nil!).first

        token.should be_a Authly::AccessToken
        it_token["user_id"].should eq "username"
      end
    end

    it "returns access_token for AuthorizationCode grant" do
      code = Authly.code("code", client_id, redirect_uri, scope, state, code_challenge, code_challenge_method).to_s
      token = Authly.access_token(
        grant_type: "authorization_code",
        client_id: client_id,
        client_secret: client_secret,
        redirect_uri: redirect_uri,
        code: code,
        state: state,
        scope: scope)

      token.should be_a Authly::AccessToken
    end

    it "returns access_token for ClientCredentials grant" do
      token = Authly.access_token(
        grant_type: "client_credentials",
        client_id: client_id,
        client_secret: client_secret,
        scope: scope)

      token.should be_a Authly::AccessToken
    end

    it "returns access_token for Password grant" do
      username = "username"
      password = "password"
      token = Authly.access_token(
        grant_type: "password",
        client_id: client_id,
        client_secret: client_secret,
        username: username,
        password: password,
        scope: scope)

      token.should be_a Authly::AccessToken
    end

    it "returns access_token for Refresh Token grant" do
      a_token = Authly::AccessToken.new(client_id, scope)
      token = Authly.access_token(
        grant_type: "refresh_token",
        client_id: client_id,
        client_secret: client_secret,
        refresh_token: a_token.refresh_token.to_s,
        scope: scope)

      token.should be_a Authly::AccessToken
    end
  end

  describe ".code" do
    it "returns an temporary code" do
      code = Authly.code("code", client_id, redirect_uri, scope, state)
      code.should be_a Authly::Code
    end

    it "raises invalid redirect uri" do
      expect_raises Authly::Error, Authly::ERROR_MSG[:invalid_redirect_uri] do
        Authly.code("code", client_id, "", scope, state)
      end
    end
  end
end
