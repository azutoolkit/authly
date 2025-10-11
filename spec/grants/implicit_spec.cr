require "../spec_helper"

module Authly
  describe "Implicit Grant" do
    client_id = "1"
    redirect_uri = "https://www.example.com/callback"
    scope = "read"

    describe "ResponseType token" do
      it "creates access token directly" do
        response = ResponseType.new("token", client_id, redirect_uri, scope, user_id: "test_user")
        token = response.token

        token.should be_a AccessToken
        token.client_id.should eq client_id
        token.scope.should eq scope
      end

      it "validates redirect_uri" do
        expect_raises Error, ERROR_MSG[:invalid_redirect_uri] do
          ResponseType.new("token", client_id, "", scope).decode
        end
      end

      it "validates client authorization" do
        expect_raises Error, ERROR_MSG[:unauthorized_client] do
          ResponseType.new("token", "invalid_client", redirect_uri, scope).decode
        end
      end
    end

    describe "Implicit flow integration" do
      it "returns access token in fragment" do
        # This test would require a full HTTP integration test
        # For now, we verify the token generation works
        response = ResponseType.new("token", client_id, redirect_uri, scope, user_id: "test_user")
        result = response.decode

        result.should be_a AccessToken
        if result.is_a?(AccessToken)
          result.access_token.should_not be_empty
          result.token_type.should eq "Bearer"
        end
      end
    end
  end
end

