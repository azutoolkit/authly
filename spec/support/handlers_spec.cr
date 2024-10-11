# Spec tests for Authly's OAuth Handlers
require "../spec_helper"
require "http/server"

module Authly
  describe "AuthorizationHandler" do
    it "returns authorization code with valid client_id and redirect_uri after user consent and includes state" do
      state = "test_state"
      # Initial Authorize Request
      initia_response = HTTP::Client.get("#{BASE_URI}/oauth/authorize?client_id=1&redirect_uri=https://www.example.com/callback&response_type=code&state=#{state}")

      # Consent Request
      response = HTTP::Client.get("#{BASE_URI}/oauth/authorize?client_id=1&redirect_uri=https://www.example.com/callback&response_type=code&state=#{state}&consent=approved")

      response.status_code.should eq 302
      response.headers["Location"].should_not be_nil
      response.headers["Location"].should contain(URI.encode_path("code="))
      response.headers["Location"].should contain(URI.encode_path("state=#{state}"))
    end

    it "renders consent page if user consent is not provided" do
      state = "test_state"
      response = HTTP::Client.get("#{BASE_URI}/oauth/authorize?client_id=1&redirect_uri=https://www.example.com/callback&response_type=code&state=#{state}")

      response.status_code.should eq 200
      response.body.should contain("Authorization Request")
      response.body.should contain("Approve")
      response.body.should contain("Deny")
      response.body.should contain(state)
    end

    it "returns 401 for invalid client_id or redirect_uri" do
      state = "test_state"
      response = HTTP::Client.get("#{BASE_URI}/oauth/authorize?client_id=invalid&redirect_uri=invalid&state=#{state}&consent=approved")
      response.status_code.should eq 401
      response.body.should eq "This client is not authorized to use the requested grant type"
    end

    it "returns 400 for invalid state parameter" do
      state = "invalid_state"
      response = HTTP::Client.get("#{BASE_URI}/oauth/authorize?client_id=1&redirect_uri=https://www.example.com/callback&response_type=code&state=#{state}&consent=approved")

      response.status_code.should eq 400
      response.body.should eq "Invalid state parameter"
    end
  end

  describe "TokenHandler" do
    it "returns access token for valid authorization_code grant" do
      code = Authly.code("code", "1", "https://www.example.com/callback", "read").to_s
      response = HTTP::Client.post("#{BASE_URI}/oauth/token", form: {
        "grant_type"    => "authorization_code",
        "client_id"     => "1",
        "client_secret" => "secret",
        "redirect_uri"  => "https://www.example.com/callback",
        "code"          => code,
      })
      response.status_code.should eq 200
      body = JSON.parse(response.body)
      body["access_token"].should_not be_nil
    end

    it "returns 400 for unsupported grant type" do
      response = HTTP::Client.post("#{BASE_URI}/oauth/token", form: {"grant_type" => "invalid_grant"})
      response.status_code.should eq 400
      response.body.should eq "Invalid or unknown grant type"
    end
  end

  describe "IntrospectHandler" do
    it "returns introspection result for valid token" do
      code = Authly.code("code", "1", "https://www.example.com/callback", "read").to_s
      token = Grant.new(
        grant_type: "authorization_code", client_id: "1", client_secret: "secret",
        redirect_uri: "https://www.example.com/callback", code: code).token

      response = HTTP::Client.post("#{BASE_URI}/introspect", form: {"token" => token.access_token})
      response.status_code.should eq 200
      body = JSON.parse(response.body)
      body.should eq({
        "active" => true,
        "scope"  => token.scope,
        "cid"    => token.client_id,
        "exp"    => token.expires_in,
        "sub"    => token.sub,
      })
    end

    it "returns 400 for missing token parameter" do
      response = HTTP::Client.post("#{BASE_URI}/introspect")
      response.status_code.should eq 400
      response.body.should eq %(Missing param name: "token")
    end
  end

  describe "RevokeHandler" do
    it "returns success message for valid token revocation" do
      access_token = Authly::AccessToken.new( "1", "read").access_token
      response = HTTP::Client.post("#{BASE_URI}/revoke", form: {"token" => access_token})
      response.status_code.should eq 200
      response.body.should eq "Token revoked successfully"
    end

    it "returns 400 for missing token parameter" do
      response = HTTP::Client.post("#{BASE_URI}/revoke")
      response.status_code.should eq 400
      response.body.should eq %(Missing param name: "token")
    end
  end
end
