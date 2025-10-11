# Spec tests for Authly's OAuth Handlers
require "../spec_helper"
require "http/server"

module Authly
  # Helper to create a test HTTP context with response capture
  class TestContext
    getter io : IO::Memory
    getter context : HTTP::Server::Context

    def initialize(method : String, path : String, query : String? = nil, form_data : Hash(String, String)? = nil)
      @io = IO::Memory.new
      request = HTTP::Request.new(method, query ? "#{path}?#{query}" : path)

      if form_data
        request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = HTTP::Params.encode(form_data)
        request.body = body
      end

      response = HTTP::Server::Response.new(@io)
      @context = HTTP::Server::Context.new(request, response)
    end

    def response_body : String
      @context.response.close
      @io.rewind
      response_text = @io.gets_to_end

      # Skip HTTP headers and return only the body
      if match = response_text.match(/\r\n\r\n(.*)$/m)
        match[1]
      else
        response_text
      end
    end
  end

  private def self.create_test_context(method : String, path : String, query : String? = nil, form_data : Hash(String, String)? = nil)
    TestContext.new(method, path, query, form_data)
  end

  describe "AuthorizationHandler" do
    it "returns authorization code with valid client_id and redirect_uri after user consent and includes state" do
      state = "test_state"

      # Initial request to store state
      query = "client_id=1&redirect_uri=https://www.example.com/callback&response_type=code&state=#{state}"
      test_ctx = create_test_context("GET", "/oauth/authorize", query)
      AuthorizationHandler.handle(test_ctx.context)

      # Consent request
      query_with_consent = "#{query}&consent=approved"
      test_ctx2 = create_test_context("GET", "/oauth/authorize", query_with_consent)
      AuthorizationHandler.handle(test_ctx2.context)

      test_ctx2.context.response.status_code.should eq 302
      test_ctx2.context.response.headers["Location"]?.should_not be_nil
      location = test_ctx2.context.response.headers["Location"]
      location.should contain("code=")
      location.should contain("state=#{state}")
    end

    it "renders consent page if user consent is not provided" do
      state = "test_state_consent"
      query = "client_id=1&redirect_uri=https://www.example.com/callback&response_type=code&state=#{state}"
      test_ctx = create_test_context("GET", "/oauth/authorize", query)

      AuthorizationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = test_ctx.response_body
      body.should contain("Authorization Request")
      body.should contain("Approve")
      body.should contain("Deny")
      body.should contain(state)
    end

    it "returns 401 for invalid client_id or redirect_uri" do
      state = "test_state_invalid_#{Random::Secure.hex(8)}"
      Authly.config.state_store.store(state)  # Store state in the configured store

      query = "client_id=invalid&redirect_uri=invalid&response_type=code&state=#{state}&consent=approved"
      test_ctx = create_test_context("GET", "/oauth/authorize", query)
      AuthorizationHandler.handle(test_ctx.context)

      # Returns 401 for unauthorized client
      test_ctx.context.response.status_code.should eq 401
      test_ctx.response_body.should eq "This client is not authorized to use the requested grant type"
    end

    it "returns 400 for invalid state parameter" do
      state = "invalid_state_not_stored"
      query = "client_id=1&redirect_uri=https://www.example.com/callback&response_type=code&state=#{state}&consent=approved"
      test_ctx = create_test_context("GET", "/oauth/authorize", query)
      AuthorizationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      test_ctx.response_body.should eq "Invalid state parameter"
    end
  end

  describe "TokenHandler" do
    it "returns access token for valid authorization_code grant" do
      code = Authly.code("code", "1", "https://www.example.com/callback", "read").to_s
      form_data = {
        "grant_type"    => "authorization_code",
        "client_id"     => "1",
        "client_secret" => "secret",
        "redirect_uri"  => "https://www.example.com/callback",
        "code"          => code,
      }
      test_ctx = create_test_context("POST", "/oauth/token", form_data: form_data)
      AccessTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body["access_token"].should_not be_nil
    end

    it "returns 400 for unsupported grant type" do
      form_data = {"grant_type" => "invalid_grant"}
      test_ctx = create_test_context("POST", "/oauth/token", form_data: form_data)
      AccessTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      test_ctx.response_body.should eq "Invalid or unknown grant type"
    end
  end

  describe "IntrospectHandler" do
    it "returns introspection result for valid token" do
      code = Authly.code("code", "1", "https://www.example.com/callback", "read").to_s
      token = Grant.new(
        grant_type: "authorization_code", client_id: "1", client_secret: "secret",
        redirect_uri: "https://www.example.com/callback", code: code).token

      form_data = {"token" => token.access_token}
      test_ctx = create_test_context("POST", "/introspect", form_data: form_data)
      IntrospectHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body.should eq({
        "active" => true,
        "scope"  => token.scope,
        "cid"    => token.client_id,
        "exp"    => token.expires_in,
        "sub"    => token.sub,
      })
    end

    it "returns 400 for missing token parameter" do
      form_data = {} of String => String
      test_ctx = create_test_context("POST", "/introspect", form_data: form_data)
      IntrospectHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      test_ctx.response_body.should contain("token")
    end
  end

  describe "RevokeHandler" do
    it "returns success message for valid token revocation" do
      access_token = Authly::AccessToken.new("1", "read").access_token
      form_data = {"token" => access_token}
      test_ctx = create_test_context("POST", "/revoke", form_data: form_data)
      RevokeHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      test_ctx.response_body.should eq "Token revoked successfully"
    end

    it "returns 400 for missing token parameter" do
      form_data = {} of String => String
      test_ctx = create_test_context("POST", "/revoke", form_data: form_data)
      RevokeHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      test_ctx.response_body.should contain("token")
    end
  end
end
