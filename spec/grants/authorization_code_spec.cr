require "../spec_helper"

module Authly
  describe AuthorizationCode do
    code_data = {
      "cid"          => "1",
      "secret"       => "secret",
      "redirect_uri" => "https://www.example.com/callback",
      "scope"        => "read",
      "state"        => "state",
    }

    describe "#authorize" do
      cid, secret, uri = code_data.values
      code = Random::Secure.hex(16)

      it "returns AccessToken" do
        authorization_code = AuthorizationCode.new(cid, secret, uri, code)
        authorization_code.authorize!.should be_a Response::AccessToken
      end

      it "raises error for invalid client credentials" do
        authorization_code = AuthorizationCode.new(cid, "invalid", uri, code)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorize!
        end
      end

      it "raises Error for client id" do
        authorization_code = AuthorizationCode.new("invalid", secret, uri, code)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorize!
        end
      end

      it "raises Error for redirect uri" do
        uri = ""
        authorization_code = AuthorizationCode.new(cid, secret, uri, code)

        expect_raises Error, ERROR_MSG[:invalid_redirect_uri] do
          authorization_code.authorize!
        end
      end
    end
  end
end
