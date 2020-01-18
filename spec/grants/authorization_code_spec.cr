require "../spec_helper"

module Authly
  describe AuthorizationCode do
    code_data = {
      "cid"          => "1",
      "secret"       => "secret",
      "redirect_uri" => "https://www.example.com/callback",
      "scope"        => "scope",
      "state"        => "state",
    }

    describe "#authorize" do
      cid, secret, uri, scope, state = code_data.values
      code = Token::Code.new(cid, uri, state, scope).to_s

      it "returns nil" do
        authorization_code = AuthorizationCode.new(cid, secret, uri, code, scope, state)
        authorization_code.authorize!.should be_a Response::AccessToken
      end

      it "raises error for invalid client credentials" do
        authorization_code = AuthorizationCode.new(cid, "invalid", uri, code, scope, state)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorize!
        end
      end

      it "raises Error for client id" do
        authorization_code = AuthorizationCode.new("invalid", secret, uri, code, scope, state)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorize!
        end
      end

      it "raises Error for redirect uri" do
        uri = ""
        authorization_code = AuthorizationCode.new(cid, secret, uri, code, scope, state)

        expect_raises Error, ERROR_MSG[:invalid_redirect_uri] do
          authorization_code.authorize!
        end
      end

      it "raises Error for state" do
        state = "invalid"
        uri = "https://www.example.com/callback"
        authorization_code = AuthorizationCode.new(cid, secret, uri, code, scope, state)

        expect_raises Error, ERROR_MSG[:invalid_state] do
          authorization_code.authorize!
        end
      end

      it "raises Error for scope" do
        scope = "invalid"
        authorization_code = AuthorizationCode.new(cid, secret, uri, code, scope, state)

        expect_raises Error(400), ERROR_MSG[:invalid_scope] do
          authorization_code.authorize!
        end
      end
    end
  end
end
