require "../spec_helper"

module Authly
  describe AuthorizationCode do
    code_data = {
      "client_id"    => "1",
      "secret"       => "secret",
      "redirect_uri" => "https://www.example.com/callback",
      "scope"        => "read",
      "state"        => "state",
    }

    describe "#authorize" do
      client_id, secret, uri, scope = code_data.values
      code_verifier = Faker::Internet.password(43, 128)

      describe "code challenge" do
        it "peforms plain code challenge authorization" do
          code_challenge = code_verifier
          code = Code.new(code_challenge, "plain", scope, "user_id", uri, client_id).to_s
          auth_code = AuthorizationCode.new(client_id, secret, uri, code, code_verifier)
          auth_code.authorized?.should be_truthy
        end

        it "peforms S256 code challenge authorization" do
          code_challenge = Digest::SHA256.base64digest(code_verifier)
          code = Code.new(code_challenge, "s256", scope, "user_id", uri, client_id).to_s
          authorization_code = AuthorizationCode.new(client_id, secret, uri, code, code_verifier)

          authorization_code.authorized?.should be_truthy
        end
      end

      it "returns true" do
        code = Code.new(client_id, scope, uri).to_s
        authorization_code = AuthorizationCode.new(client_id, secret, uri, code)
        authorization_code.authorized?.should be_truthy
      end

      it "raises error for invalid client credentials" do
        code = Code.new(client_id, scope, uri).to_s
        authorization_code = AuthorizationCode.new(client_id, "invalid", uri, code)

        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          authorization_code.authorized?
        end
      end

      it "raises Error for client id" do
        code = Code.new(client_id, scope, uri).to_s
        authorization_code = AuthorizationCode.new("invalid_client", "invalid_client_secret", uri, code)

        expect_raises Error, ERROR_MSG[:invalid_redirect_uri] do
          authorization_code.authorized?
        end
      end

      it "raises Error for redirect uri" do
        code = Code.new(client_id, scope, uri).to_s
        authorization_code = AuthorizationCode.new(client_id, secret, "", code)

        expect_raises Error, ERROR_MSG[:invalid_redirect_uri] do
          authorization_code.authorized?
        end
      end
    end
  end
end
