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
      state = Random::Secure.hex
      code_verifier = Faker::Internet.password(43, 128)

      describe "code challenge" do
        it "peforms plain code challenge authorization" do
          code_challenge = code_verifier
          code = Code.new(code_challenge, "plain").to_s
          auth_code = AuthorizationCode.new(cid, secret, uri, code, code_verifier)
          auth_code.authorized?.should be_truthy
        end

        it "peforms S256 code challenge authorization" do
          code_challenge = Digest::SHA256.base64digest(code_verifier)
          code = Code.new(code_challenge, "S256").to_s
          authorization_code = AuthorizationCode.new(cid, secret, uri, code, code_verifier)

          authorization_code.authorized?.should be_truthy
        end
      end

      it "returns false" do
        code = Code.new.to_s
        authorization_code = AuthorizationCode.new(cid, secret, uri, code)
        authorization_code.authorized?.should be_truthy
      end

      it "raises error for invalid client credentials" do
        code = Code.new.to_s
        authorization_code = AuthorizationCode.new(cid, "invalid", uri, code)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorized?
        end
      end

      it "raises Error for client id" do
        code = Code.new.to_s
        authorization_code = AuthorizationCode.new("invalid", secret, uri, code)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorized?
        end
      end

      it "raises Error for redirect uri" do
        code = Code.new.to_s
        uri = ""
        authorization_code = AuthorizationCode.new(cid, secret, uri, code)

        expect_raises Error, ERROR_MSG[:invalid_redirect_uri] do
          authorization_code.authorized?
        end
      end
    end
  end
end
