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
      Authly.config.state_store.store(state) # Store state in the configured store

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

    it "actually revokes the token" do
      access_token = Authly::AccessToken.new("1", "read").access_token

      # Verify token is valid before revocation
      Authly.valid?(access_token).should be_true

      form_data = {"token" => access_token}
      test_ctx = create_test_context("POST", "/revoke", form_data: form_data)
      RevokeHandler.handle(test_ctx.context)

      # Token should be revoked after
      Authly.revoked?(access_token).should be_true
    end
  end

  describe "DeviceAuthorizationHandler" do
    before_each do
      Authly.config.device_code_store = InMemoryDeviceCodeStore.new
    end

    it "returns device authorization for valid client_id" do
      form_data = {"client_id" => "1", "scope" => "read write"}
      test_ctx = create_test_context("POST", "/device/code", form_data: form_data)
      DeviceAuthorizationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body["device_code"].should_not be_nil
      body["user_code"].should_not be_nil
      body["verification_uri"].should_not be_nil
      body["expires_in"].should eq 900
      body["interval"].should_not be_nil
    end

    it "returns device code and user code in correct format" do
      form_data = {"client_id" => "1", "scope" => "read"}
      test_ctx = create_test_context("POST", "/device/code", form_data: form_data)
      DeviceAuthorizationHandler.handle(test_ctx.context)

      body = JSON.parse(test_ctx.response_body)
      # User code should be 9 characters in format XXXX-XXXX
      body["user_code"].as_s.size.should eq 9
      body["user_code"].as_s.should match(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)
      # Device code should be a hex string
      body["device_code"].as_s.should match(/^[a-f0-9]+$/)
    end

    it "includes verification_uri_complete with user_code" do
      form_data = {"client_id" => "1"}
      test_ctx = create_test_context("POST", "/device/code", form_data: form_data)
      DeviceAuthorizationHandler.handle(test_ctx.context)

      body = JSON.parse(test_ctx.response_body)
      uri_complete = body["verification_uri_complete"].as_s
      user_code = body["user_code"].as_s

      uri_complete.should contain(user_code)
      uri_complete.should contain("user_code=")
    end

    it "returns 401 for invalid client_id" do
      form_data = {"client_id" => "invalid_client_999"}
      test_ctx = create_test_context("POST", "/device/code", form_data: form_data)
      DeviceAuthorizationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 401
      body = JSON.parse(test_ctx.response_body)
      body["error"].should eq "invalid_client"
    end

    it "returns 400 for missing client_id parameter" do
      form_data = {} of String => String
      test_ctx = create_test_context("POST", "/device/code", form_data: form_data)
      DeviceAuthorizationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      body = JSON.parse(test_ctx.response_body)
      body["error"].should eq "invalid_request"
    end

    it "uses default scope when not provided" do
      form_data = {"client_id" => "1"}
      test_ctx = create_test_context("POST", "/device/code", form_data: form_data)
      DeviceAuthorizationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      # Should succeed with default scope
      body = JSON.parse(test_ctx.response_body)
      body["device_code"].should_not be_nil
    end
  end

  describe "DeviceVerificationHandler" do
    before_each do
      Authly.config.device_code_store = InMemoryDeviceCodeStore.new
    end

    it "handles GET request and renders verification page" do
      test_ctx = create_test_context("GET", "/device", nil)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = test_ctx.response_body
      body.should contain("Device Verification")
      body.should contain("Enter the code shown on your device")
      body.should contain("Approve")
      body.should contain("Deny")
    end

    it "pre-fills user_code in GET request when provided" do
      query = "user_code=ABCD-1234"
      test_ctx = create_test_context("GET", "/device", query)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = test_ctx.response_body
      body.should contain("ABCD-1234")
    end

    it "handles POST approve action successfully" do
      # Create a device code first
      device_data = DeviceCode.create_device_authorization("1", "read")

      form_data = {
        "user_code" => device_data.user_code,
        "user_id"   => "test_user",
        "action"    => "approve",
      }
      test_ctx = create_test_context("POST", "/device", form_data: form_data)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = test_ctx.response_body
      body.should contain("Device Authorized!")
    end

    it "handles POST deny action successfully" do
      device_data = DeviceCode.create_device_authorization("1", "read")

      form_data = {
        "user_code" => device_data.user_code,
        "user_id"   => "test_user",
        "action"    => "deny",
      }
      test_ctx = create_test_context("POST", "/device", form_data: form_data)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = test_ctx.response_body
      body.should contain("Access Denied")
    end

    it "handles denial correctly" do
      device_data = DeviceCode.create_device_authorization("1", "read")

      form_data = {
        "user_code" => device_data.user_code,
        "user_id"   => "test_user",
        "action"    => "deny",
      }
      test_ctx = create_test_context("POST", "/device", form_data: form_data)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = test_ctx.response_body
      body.should contain("Access Denied")
    end

    it "returns error for invalid user_code" do
      form_data = {
        "user_code" => "INVALID",
        "user_id"   => "test_user",
        "action"    => "approve",
      }
      test_ctx = create_test_context("POST", "/device", form_data: form_data)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      body = test_ctx.response_body
      body.should contain("Invalid or expired user code")
    end

    it "returns error for expired device code" do
      device_data = DeviceCode.create_device_authorization("1", "read")
      # Store but don't use it immediately
      Authly.config.device_code_store.store(device_data.device_code, device_data)

      # Delete it to simulate expiration
      Authly.config.device_code_store.delete(device_data.device_code)

      form_data = {
        "user_code" => device_data.user_code,
        "user_id"   => "test_user",
        "action"    => "approve",
      }
      test_ctx = create_test_context("POST", "/device", form_data: form_data)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
    end

    it "returns 405 for unsupported HTTP methods" do
      test_ctx = create_test_context("PUT", "/device", nil)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 405
      test_ctx.response_body.should eq "Method not allowed"
    end

    it "normalizes user_code by uppercasing" do
      device_data = DeviceCode.create_device_authorization("1", "read")

      # Submit user code in lowercase
      form_data = {
        "user_code" => device_data.user_code.downcase,
        "user_id"   => "test_user",
        "action"    => "approve",
      }
      test_ctx = create_test_context("POST", "/device", form_data: form_data)
      DeviceVerificationHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
    end
  end

  describe "RefreshTokenHandler" do
    it "returns new access token for valid refresh token" do
      # Create initial token
      token = Authly::AccessToken.new("1", "read")

      form_data = {
        "client_id"     => "1",
        "client_secret" => "secret",
        "refresh_token" => token.refresh_token,
      }
      test_ctx = create_test_context("POST", "/oauth/refresh", form_data: form_data)
      RefreshTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body["access_token"].should_not be_nil
      body["refresh_token"].should_not be_nil
    end

    it "returns 400 for missing client_id parameter" do
      form_data = {
        "client_secret" => "secret",
        "refresh_token" => "token",
      }
      test_ctx = create_test_context("POST", "/oauth/refresh", form_data: form_data)
      RefreshTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      body = JSON.parse(test_ctx.response_body)
      body["error"].should eq "missing_parameters"
    end

    it "returns 400 for missing client_secret parameter" do
      form_data = {
        "client_id"     => "1",
        "refresh_token" => "token",
      }
      test_ctx = create_test_context("POST", "/oauth/refresh", form_data: form_data)
      RefreshTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      body = JSON.parse(test_ctx.response_body)
      body["error"].should eq "missing_parameters"
    end

    it "returns 400 for missing refresh_token parameter" do
      form_data = {
        "client_id"     => "1",
        "client_secret" => "secret",
      }
      test_ctx = create_test_context("POST", "/oauth/refresh", form_data: form_data)
      RefreshTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 400
      body = JSON.parse(test_ctx.response_body)
      body["error"].should eq "missing_parameters"
    end

    it "returns error for invalid credentials" do
      token = Authly::AccessToken.new("1", "read")

      form_data = {
        "client_id"     => "1",
        "client_secret" => "wrong_secret",
        "refresh_token" => token.refresh_token,
      }
      test_ctx = create_test_context("POST", "/oauth/refresh", form_data: form_data)
      RefreshTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should_not eq 200
      body = JSON.parse(test_ctx.response_body)
      body["error"].should_not be_nil
    end
  end

  describe "AccessTokenHandler - Enhanced Coverage" do
    it "handles client_credentials grant type" do
      form_data = {
        "grant_type"    => "client_credentials",
        "client_id"     => "1",
        "client_secret" => "secret",
        "scope"         => "read",
      }
      test_ctx = create_test_context("POST", "/oauth/token", form_data: form_data)
      AccessTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body["access_token"].should_not be_nil
      body["token_type"].should eq "Bearer"
    end

    it "handles password grant type" do
      form_data = {
        "grant_type"    => "password",
        "username"      => "john",
        "password"      => "secret",
        "scope"         => "read",
        "client_id"     => "1",
        "client_secret" => "secret",
      }
      test_ctx = create_test_context("POST", "/oauth/token", form_data: form_data)
      AccessTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body["access_token"].should_not be_nil
    end

    it "returns error for missing required parameters" do
      form_data = {"grant_type" => "authorization_code"}
      test_ctx = create_test_context("POST", "/oauth/token", form_data: form_data)
      AccessTokenHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should_not eq 200
    end
  end

  describe "IntrospectHandler - Enhanced Coverage" do
    it "returns active=false for expired token" do
      # Create a token with very short TTL
      original_ttl = Authly.config.access_ttl
      Authly.config.access_ttl = -1.seconds # Already expired

      token = Authly::AccessToken.new("1", "read")

      # Restore original TTL
      Authly.config.access_ttl = original_ttl

      form_data = {"token" => token.access_token}
      test_ctx = create_test_context("POST", "/introspect", form_data: form_data)
      IntrospectHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body["active"].should eq false
    end

    it "returns active=false for revoked token" do
      # Create a fresh token with unique client
      token = Authly::AccessToken.new("1", "read")
      access_token_str = token.access_token

      # Revoke it
      Authly.revoke(access_token_str)

      # Verify it's marked as revoked
      Authly.revoked?(access_token_str).should be_true

      # Now introspect should return active=false
      form_data = {"token" => access_token_str}
      test_ctx = create_test_context("POST", "/introspect", form_data: form_data)
      IntrospectHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body["active"].should eq false
    end

    it "returns active=false for invalid token format" do
      form_data = {"token" => "invalid_token_format"}
      test_ctx = create_test_context("POST", "/introspect", form_data: form_data)
      IntrospectHandler.handle(test_ctx.context)

      test_ctx.context.response.status_code.should eq 200
      body = JSON.parse(test_ctx.response_body)
      body["active"].should eq false
    end
  end
end
