require "../spec_helper"

module Authly
  cid, secret, username, password, scope = "1", "secret", "username", "password", "read write"

  describe Password do
    password_authorization = Password.new(
      client_id: cid, client_secret: secret, username: username, password: password, scope: scope
    )

    it "returns nil" do
      (password_authorization.authorize!).should be_a AccessToken
    end

    it "raises error for invalid client credentials" do
      invalid_auth = Password.new(
        client_id: cid, client_secret: "bad secret", username: username, password: password, scope: scope
      )

      expect_raises OAuthError, ERROR_MSG[:unauthorized_client] do
        invalid_auth.authorize!
      end
    end

    it "raises error for invalid owner credentials" do
      invalid_owner = Password.new(
        client_id: cid, client_secret: secret, username: username, password: "bad password", scope: scope
      )

      expect_raises OAuthError, ERROR_MSG[:owner_credentials] do
        invalid_owner.authorize!
      end
    end
  end
end