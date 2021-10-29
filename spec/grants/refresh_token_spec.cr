require "../spec_helper"

module Authly
  describe RefreshToken do
    cid, secret, scope = "1", "secret", "read write"
    token = AccessToken.new(cid, scope).refresh_token

    refresh_token = RefreshToken.new(
      client_id: cid, client_secret: secret, refresh_token: token, scope: scope,
    )

    it "returns RefreshToken" do
      refresh_token.authorized?.should be_a AccessToken
    end

    it "raises error for invalid client credentials" do
      refresh_token = RefreshToken.new(
        client_id: cid, client_secret: "BAD", refresh_token: token, scope: scope,
      )

      expect_raises Error, ERROR_MSG[:unauthorized_client] do
        refresh_token.authorized?
      end
    end
  end
end
