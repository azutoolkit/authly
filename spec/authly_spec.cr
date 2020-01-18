require "./spec_helper"

describe Authly do
  cid = "1"
  state = "state"
  scope = "scope"
  uri = "https://www.example.com/callback"

  describe ".response" do
    it "returns an temporary token" do
      (Authly.response("code", cid, uri, scope, state)).should be_a Authly::Response::Code
    end

    it "raises invalid redirect uri" do
      expect_raises Authly::Error, Authly::ERROR_MSG[:invalid_redirect_uri] do
        Authly.response("code", cid, "", scope, state)
      end
    end
  end
end
