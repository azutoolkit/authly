require "../spec_helper"

module Authly
  describe ClientCredentials do
    cid, secret = "1", "secret"

    it "returns nil" do
      client_credentials = ClientCredentials.new(
        client_id: cid, client_secret: secret, scope: ""
      )
      client_credentials.authorize!.should be_a AccessToken
    end

    it "raises error for invalid client credentials" do
      client_credentials = ClientCredentials.new(
        client_id: cid, client_secret: "invalid", scope: ""
      )
      expect_raises OAuthError, ERROR_MSG[:unauthorized_client] do
        client_credentials.authorize!
      end
    end
  end
end
