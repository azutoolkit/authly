require "../spec_helper"

module Authly
  describe ClientCredentialsGrant do
    cid, secret = "1", "secret"

    it "returns AccessToken" do
      client_credentials = ClientCredentialsGrant.new(
        client_id: cid, client_secret: secret
      )
      client_credentials.authorized?.should be_truthy
    end

    it "raises error for invalid client credentials" do
      client_credentials = ClientCredentialsGrant.new(
        client_id: cid, client_secret: "invalid"
      )
      expect_raises Error, ERROR_MSG[:unauthorized_client] do
        client_credentials.authorized?
      end
    end
  end
end
