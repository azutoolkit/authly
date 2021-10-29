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

      describe "code challenge" do
        code = Random::Secure.hex(32)
        code_verifier = Base64.urlsafe_encode(code).gsub(/{\+|\=|\/}/, "")
        code_challenge = Digest::SHA256.base64digest(code_verifier)

        it "peforms plain code challenge authorization" do
          authorization_code = AuthorizationCode.new(cid, secret, uri, code, code_challenge, "plain")
          token = authorization_code.authorized?

          token.should be_a AccessToken
        end

        it "peforms S256 code challenge authorization" do
          authorization_code = AuthorizationCode.new(cid, secret, uri, code, code_challenge, "S256")
          token = authorization_code.authorized?

          token.should be_a AccessToken
        end
      end

      it "returns AccessToken" do
        authorization_code = AuthorizationCode.new(cid, secret, uri, code)
        authorization_code.authorized?.should be_a AccessToken
      end

      it "raises error for invalid client credentials" do
        authorization_code = AuthorizationCode.new(cid, "invalid", uri, code)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorized?
        end
      end

      it "raises Error for client id" do
        authorization_code = AuthorizationCode.new("invalid", secret, uri, code)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorized?
        end
      end

      it "raises Error for redirect uri" do
        uri = ""
        authorization_code = AuthorizationCode.new(cid, secret, uri, code)

        expect_raises Error, ERROR_MSG[:invalid_redirect_uri] do
          authorization_code.authorized?
        end
      end
    end
  end
end
