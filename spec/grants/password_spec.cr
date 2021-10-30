require "../spec_helper"

module Authly
  cid, secret, username, password, scope = "1", "secret", "username", "password", "read"

  describe Password do
    password_authorization = Password.new(
      client_id: cid, client_secret: secret, username: username, password: password, scope: scope
    )

    it "returns AccessToken" do
      password_authorization.authorized?.should be_truthy
    end

    it "raises error for invalid client credentials" do
      invalid_auth = Password.new(
        client_id: cid, client_secret: "bad secret", username: username, password: password, scope: scope
      )

      expect_raises Error, ERROR_MSG[:unauthorized_client] do
        invalid_auth.authorized?
      end
    end

    it "raises error for invalid owner credentials" do
      invalid_owner = Password.new(
        client_id: cid, client_secret: secret, username: username, password: "bad password", scope: scope
      )

      expect_raises Error, ERROR_MSG[:owner_credentials] do
        invalid_owner.authorized?
      end
    end
  end
end
