require "./spec_helper"

module Authly
  describe GrantStrategy do
    client_id = "1"
    client_secret = "secret"
    state = "state"
    scope = "scope"
    redirect_uri = "https://www.example.com/callback"
    username = "username"
    password = "password"
    refresh_token = ""

    describe ".strategy" do
      it "returns an Authorization Code" do
        code = Token::Code.new(client_id, redirect_uri, state, scope)
        strategy = GrantStrategy.parse("authorization_code").strategy(
          client_id: client_id,
          client_secret: client_secret,
          redirect_uri: redirect_uri,
          code: code.to_s,
          state: state,
          scope: scope
        )

        strategy.should be_a AuthorizationCode
      end

      it "returns a Client Credentials" do
        strategy = GrantStrategy.parse("client_credentials").strategy(
          client_id: client_id,
          client_secret: client_secret,
          scope: scope
        )

        strategy.should be_a ClientCredentials
      end

      it "returns a Password" do
        strategy = GrantStrategy.parse("password").strategy(
          client_id: client_id,
          client_secret: client_secret,
          scope: scope,
          username: username,
          password: password
        )

        strategy.should be_a Password
      end

      it "returns a RefreshToken" do
        strategy = GrantStrategy.parse("refresh_token").strategy(
          client_id: client_id,
          client_secret: client_secret,
          scope: scope,
          refresh_token: refresh_token,
        )

        strategy.should be_a RefreshToken
      end
    end
  end
end
