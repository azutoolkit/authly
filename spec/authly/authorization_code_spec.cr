require "../spec_helper"

module Authly
  describe AuthorizationCode do
    describe "#authorize" do
      cid, secret, uri, scope, state = "1", "secret", URI.parse("https://www.example.com/callback"), "scope", "state"
      code = Token.write cid, uri.to_s, 1.minute.from_now.to_unix, state, scope

      it "returns AccessToken" do
        authorization_code = AuthorizationCode.new(cid, secret, uri, code, scope, state)
        authorization_code.authorize!.should be_a AccessToken
      end

      it "raises error for invalid client credentials" do
        authorization_code = AuthorizationCode.new(cid, "invalid", uri, code, scope, state)
        expect_raises OAuthError, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorize!
        end
      end

      it "raises Error for client id" do
        authorization_code = AuthorizationCode.new("invalid", secret, uri, code, scope, state)

        expect_raises OAuthError, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorize!
        end
      end

      it "raises Error for redirect uri" do
        uri = URI.parse("invalid")
        cid = "1"
        authorization_code = AuthorizationCode.new(cid, secret, uri, code, scope, state)
        expect_raises OAuthError, ERROR_MSG[:invalid_redirect_uri] do
          authorization_code.authorize!
        end
      end

      it "raises Error for state" do
        state = "invalid"
        uri = URI.parse("https://www.example.com/callback")
        authorization_code = AuthorizationCode.new(cid, secret, uri, code, scope, state)

        expect_raises OAuthError, ERROR_MSG[:invalid_state] do
          authorization_code.authorize!
        end
      end

      it "raises Error for scope" do
        scope = "invalid"
        cid = "1"
        uri = URI.parse("https://www.example.com/callback")
        authorization_code = AuthorizationCode.new(cid, secret, uri, code, scope, state)

        expect_raises OAuthError, ERROR_MSG[:invalid_scope] do
          authorization_code.authorize!
        end
      end
    end
  end
end
