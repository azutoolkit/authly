require "./spec_helper"

describe Authly do
  cid = "1"
  secret = "secret"
  state = "state"
  scope = "scope"
  exp = 1.minute.from_now.to_unix
  uri = URI.parse("https://www.example.com/callback")

  describe ".authorize" do
    grant = "authorization_code"
    code = Authly::Token.new(cid, exp, uri.to_s, state, scope).to_s

    it "returns an access token" do
      request = {grant, cid, secret, uri, code, scope, state}
      (Authly.authorize(*request)).should be_a Authly::AccessToken
    end

    it "raises invalid redirect uri" do
      request = {grant, cid, secret, URI.parse("BAD"), code, scope, state}

      expect_raises Authly::OAuthError, Authly::ERROR_MSG[:invalid_redirect_uri] do
        Authly.authorize(*request)
      end
    end
  end

  describe ".code" do
    it "returns an temporary token" do
      request = build_temporary_code(authorized: true)
      (Authly.code(request) { true }).should be_a Authly::TemporaryCode
    end

    it "raises invalid redirect uri" do
      request = build_temporary_code(redirect_uri: URI.parse("bad"))
      expect_raises Authly::OAuthError, Authly::ERROR_MSG[:invalid_redirect_uri] do
        Authly.code(request) { false }
      end
    end
  end
end
