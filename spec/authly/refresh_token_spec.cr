require "../spec_helper"

module Authly
  describe RefreshToken do
    cid, secret, scope = "1", "secret", "read write"
    token = Token.new(cid, 1.minute.from_now.to_unix, scope: scope).to_s
    refresh_token = RefreshToken.new(
      client_id: cid, client_secret: secret, refresh_token: token, scope: scope,
    )

    it "returns nil" do
      refresh_token.authorize!.should be_a AccessToken
    end

    it "raises error for invalid client credentials" do
      refresh_token = RefreshToken.new(
        client_id: cid, client_secret: "invalid", refresh_token: token, scope: scope,
      )
      expect_raises OAuthError, ERROR_MSG[:unauthorized_client] do
        refresh_token.authorize!
      end
    end
  end
end
