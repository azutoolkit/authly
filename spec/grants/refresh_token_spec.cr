require "../spec_helper"

module Authly
  describe RefreshToken do
    client_id, secret, scope = "1", "secret", "read write"

    it "returns RefreshToken" do
      token = AccessToken.new(client_id, scope).refresh_token
      refresh_token = RefreshToken.new(
        client_id: client_id, client_secret: secret, refresh_token: token,
      )
      refresh_token.authorized?.should be_truthy
    end

    it "raises error for invalid client credentials" do
      token = AccessToken.new(client_id, scope).refresh_token

      refresh_token = RefreshToken.new(
        client_id: client_id, client_secret: "BAD", refresh_token: token
      )

      expect_raises Error, ERROR_MSG[:unauthorized_client] do
        refresh_token.authorized?
      end
    end
  end
end
