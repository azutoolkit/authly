require "./spec_helper"

describe Authly do
  client_id = "1"
  client_secret = "secret"
  state = "state"
  scope = "scope"
  redirect_uri = "https://www.example.com/callback"

  describe ".access_token" do
    it "returns access_token for AuthorizationCode grant" do
      code = Authly.code("code", client_id, redirect_uri, scope, state).to_json
      token = Authly.token(
        grant_type: "authorization_code",
        client_id: client_id,
        client_secret: client_secret,
        redirect_uri: redirect_uri,
        code: code,
        state: state,
        scope: scope)

      token.should be_a Authly::Response::AccessToken
    end

    it "returns access_token for ClientCredentials grant" do
      token = Authly.token(
        grant_type: "client_credentials",
        client_id: client_id,
        client_secret: client_secret,
        scope: scope)

      token.should be_a Authly::Response::AccessToken
    end

    it "returns access_token for Password grant" do
      username = "username"
      password = "password"
      token = Authly.token(
        grant_type: "password",
        client_id: client_id,
        client_secret: client_secret,
        username: username,
        password: password,
        scope: scope)

      token.should be_a Authly::Response::AccessToken
    end

    it "returns access_token for Refresh Token grant" do
      a_token = Authly::Response::AccessToken.new(client_id)
      token = Authly.token(
        grant_type: "refresh_token",
        client_id: client_id,
        client_secret: client_secret,
        refresh_token: a_token.refresh_token.to_s,
        scope: scope)

      token.should be_a Authly::Response::AccessToken
    end
  end

  describe ".code" do
    it "returns an temporary code" do
      code = Authly.code("code", cid, uri, scope, state)
      code.should be_a Authly::Response::Code
    end

    it "raises invalid redirect uri" do
      expect_raises Authly::Error, Authly::ERROR_MSG[:invalid_redirect_uri] do
        Authly.response("code", cid, "", scope, state)
      end
    end
  end
end
