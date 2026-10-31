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
          code = Code.new(client_id, scope, uri, code_challenge, "plain", "user_id").to_s
          auth_code = AuthorizationCode.new(client_id, secret, uri, code, code_verifier)
          auth_code.authorized?.should be_truthy
        end

        it "peforms S256 code challenge authorization" do
          code_challenge = Digest::SHA256.base64digest(code_verifier)
          code = Code.new(client_id, scope, uri, code_challenge, "S256", "user_id").to_s
          authorization_code = AuthorizationCode.new(client_id, secret, uri, code, code_verifier)

          authorization_code.authorized?.should be_truthy
        end
      end

      describe "PKCE enforcement" do
        it "rejects a code that carries a challenge when no verifier is sent" do
          challenge = Digest::SHA256.base64digest(code_verifier)
          code = Code.new(client_id, scope, uri, challenge, "S256", "user_id").to_s
          authorization_code = AuthorizationCode.new(client_id, secret, uri, code)

          expect_raises Error, ERROR_MSG[:unauthorized_client] do
            authorization_code.authorized?
          end
        end

        it "rejects a request that carries no code" do
          authorization_code = AuthorizationCode.new(client_id, secret, uri)

          expect_raises Error, ERROR_MSG[:invalid_grant] do
            authorization_code.authorized?
          end
        end
      end

      describe "single use" do
        it "rejects a code that was already redeemed" do
          code = Code.new(client_id, scope, uri).to_s
          AuthorizationCode.new(client_id, secret, uri, code).authorized?.should be_true

          expect_raises Error, ERROR_MSG[:invalid_grant] do
            AuthorizationCode.new(client_id, secret, uri, code).authorized?
          end
        end

        it "does not consume a code when the request is rejected" do
          challenge = Digest::SHA256.base64digest(code_verifier)
          code = Code.new(client_id, scope, uri, challenge, "S256", "user_id").to_s

          expect_raises(Error) { AuthorizationCode.new(client_id, secret, uri, code).authorized? }
          AuthorizationCode.new(client_id, secret, uri, code, code_verifier).authorized?.should be_true
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

        expect_raises Error, ERROR_MSG[:invalid_grant] do
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
