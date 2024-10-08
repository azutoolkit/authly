require "../spec_helper"

module Authly
  cid, secret, username, password = "1", "secret", "username", "password"

  describe PasswordGrant do
    password_authorization = PasswordGrant.new(
      client_id: cid, client_secret: secret, username: username, password: password
    )

    it "returns AccessToken" do
      password_authorization.authorized?.should be_truthy
    end

    it "raises error for invalid client credentials" do
      invalid_auth = PasswordGrant.new(
        client_id: cid, client_secret: "bad secret", username: username, password: password
      )

      expect_raises Error, ERROR_MSG[:unauthorized_client] do
        invalid_auth.authorized?
      end
    end

    it "raises error for invalid owner credentials" do
      invalid_owner = PasswordGrant.new(
        client_id: cid, client_secret: secret, username: username, password: "bad password"
      )

      expect_raises Error, ERROR_MSG[:owner_credentials] do
        invalid_owner.authorized?
      end
    end
  end
end
