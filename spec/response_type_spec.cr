require "./spec_helper"

module Authly
  describe ResponseType do
    before_each do
      # Setup test client
      Authly.config.clients = Clients.new
      Authly.config.clients << Client.new("TestApp", "secret", "https://example.com/callback", "client_1", "read write", "authorization_code implicit")
      Authly.config.clients << Client.new("example", "secret", "https://www.example.com/callback", "1", "read write admin openid", "authorization_code client_credentials password refresh_token implicit")
    end

    describe "#initialize" do
      it "creates response type with required parameters" do
        rt = ResponseType.new("code", "client_1", "https://example.com/callback", "read")

        rt.type.should eq "code"
        rt.client_id.should eq "client_1"
        rt.redirect_uri.should eq "https://example.com/callback"
        rt.scope.should eq "read"
      end

      it "accepts optional challenge parameters" do
        rt = ResponseType.new(
          "code",
          "client_1",
          "https://example.com/callback",
          "read",
          "challenge_abc",
          "S256",
          "user_123"
        )

        rt.challenge.should eq "challenge_abc"
        rt.challenge_method.should eq "S256"
        rt.user_id.should eq "user_123"
      end

      it "has empty strings for optional parameters by default" do
        rt = ResponseType.new("code", "client_1", "https://example.com/callback", "read")

        rt.challenge.should eq ""
        rt.challenge_method.should eq ""
        rt.user_id.should eq ""
      end
    end

    describe "#decode" do
      context "with code response type" do
        it "returns Code object for valid request" do
          rt = ResponseType.new("code", "client_1", "https://example.com/callback", "read")

          result = rt.decode
          result.should be_a(Code)
        end

        it "includes all parameters in Code object" do
          rt = ResponseType.new("code", "client_1", "https://example.com/callback", "read write")

          code = rt.decode.as(Code)
          code.client_id.should eq "client_1"
          code.scope.should eq "read write"
          code.redirect_uri.should eq "https://example.com/callback"
        end

        it "includes PKCE parameters if provided" do
          rt = ResponseType.new(
            "code",
            "client_1",
            "https://example.com/callback",
            "read",
            "challenge_value",
            "S256",
            "user_1"
          )

          code = rt.decode.as(Code)
          code.challenge.should eq "challenge_value"
          code.method.should eq "S256"
          code.user_id.should eq "user_1"
        end
      end

      context "with token response type" do
        it "returns AccessToken object for valid request" do
          rt = ResponseType.new("token", "client_1", "https://example.com/callback", "read")

          result = rt.decode
          result.should be_a(AccessToken)
        end

        it "includes client_id and scope in AccessToken" do
          rt = ResponseType.new("token", "client_1", "https://example.com/callback", "read write")

          token = rt.decode.as(AccessToken)
          token.client_id.should eq "client_1"
          token.scope.should eq "read write"
        end
      end

      context "authorization checks" do
        it "raises error for invalid redirect_uri" do
          rt = ResponseType.new("code", "client_1", "https://malicious.com/callback", "read")

          expect_raises(Error, "This client is not authorized to use the requested grant type") do
            rt.decode
          end
        end

        it "raises error for empty redirect_uri" do
          rt = ResponseType.new("code", "client_1", "", "read")

          expect_raises(Error, "Invalid redirect uri") do
            rt.decode
          end
        end

        it "raises error for invalid client_id" do
          rt = ResponseType.new("code", "invalid_client", "https://example.com/callback", "read")

          expect_raises(Error, "This client is not authorized to use the requested grant type") do
            rt.decode
          end
        end

        it "raises error when client and redirect don't match" do
          Authly.config.clients << Client.new("App2", "secret2", "https://app2.com/callback", "client_2")
          rt = ResponseType.new("code", "client_1", "https://app2.com/callback", "read")

          expect_raises(Error, "This client is not authorized to use the requested grant type") do
            rt.decode
          end
        end
      end
    end

    describe "#code" do
      it "creates Code object directly" do
        rt = ResponseType.new("code", "client_1", "https://example.com/callback", "read")

        code = rt.code
        code.should be_a(Code)
        code.client_id.should eq "client_1"
      end
    end

    describe "#token" do
      it "creates AccessToken object directly" do
        rt = ResponseType.new("token", "client_1", "https://example.com/callback", "read")

        token = rt.token
        token.should be_a(AccessToken)
        token.client_id.should eq "client_1"
      end
    end
  end
end
